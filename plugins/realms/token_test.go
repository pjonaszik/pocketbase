package realms_test

import (
	"net/http/httptest"
	"testing"
	"time"

	"github.com/pocketbase/pocketbase/apis"
	"github.com/pocketbase/pocketbase/core"
	"github.com/pocketbase/pocketbase/plugins/realms"
	"github.com/pocketbase/pocketbase/tests"
	"github.com/pocketbase/pocketbase/tools/security"
)

func setupToken(t *testing.T) (*tests.TestApp, *core.Record, *core.Record) {
	t.Helper()
	app := setupUsers(t)
	realm := newRealm(t, app, "acme")

	col, err := app.FindCollectionByNameOrId(realms.CollectionUsers)
	if err != nil {
		t.Fatal(err)
	}
	u := core.NewRecord(col)
	u.Set(realms.FieldRealm, realm.Id)
	u.Set(realms.FieldIdentity, "bob@example.com")
	u.SetPassword("password1234")
	if err := app.Save(u); err != nil {
		t.Fatal(err)
	}
	return app, realm, u
}

func realmToken(t *testing.T, app core.App, user *core.Record) string {
	t.Helper()
	stock, err := user.NewAuthToken()
	if err != nil {
		t.Fatal(err)
	}
	tok, err := realms.ReSignRealmToken(app, user, stock)
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func TestSignRealmTokenUsesRealmSecret(t *testing.T) {
	app, realm, user := setupToken(t)
	defer app.Cleanup()

	token := realmToken(t, app, user)

	// it must verify with the realm secret...
	if _, err := security.ParseJWT(token, user.TokenKey()+realm.GetString("authSecret")); err != nil {
		t.Fatalf("token must verify with the realm secret: %v", err)
	}
	// ...and NOT with the collection secret (that is the whole point)
	if _, err := security.ParseJWT(token, user.TokenKey()+user.Collection().AuthToken.Secret); err == nil {
		t.Fatal("token must NOT verify with the collection secret")
	}
	// and it must carry the realm claim
	claims, err := security.ParseUnverifiedJWT(token)
	if err != nil {
		t.Fatal(err)
	}
	if claims[realms.ClaimRealm] != realm.Id {
		t.Fatalf("expected realm claim %q, got %v", realm.Id, claims[realms.ClaimRealm])
	}
}

func TestVerifyRealmTokenRoundTrip(t *testing.T) {
	app, _, user := setupToken(t)
	defer app.Cleanup()

	token := realmToken(t, app, user)
	got, err := realms.VerifyRealmToken(app, token)
	if err != nil {
		t.Fatalf("VerifyRealmToken: %v", err)
	}
	if got == nil || got.Id != user.Id {
		t.Fatalf("expected to resolve user %s, got %v", user.Id, got)
	}
}

func TestVerifyRealmTokenRejectsWrongSecret(t *testing.T) {
	app, realm, user := setupToken(t)
	defer app.Cleanup()

	// a token forged with a wrong secret must not verify
	forged, err := security.NewJWT(map[string]any{
		core.TokenClaimId:           user.Id,
		core.TokenClaimCollectionId: user.Collection().Id,
		core.TokenClaimType:         core.TokenTypeAuth,
		realms.ClaimRealm:           realm.Id,
	}, user.TokenKey()+"a_wrong_secret_padding_0123456789", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := realms.VerifyRealmToken(app, forged); err == nil {
		t.Fatal("expected a token signed with the wrong secret to be rejected")
	}
}

func TestVerifyRealmTokenRejectsCrossRealm(t *testing.T) {
	app, realm, user := setupToken(t)
	defer app.Cleanup()

	other := newRealm(t, app, "beta")

	// a token whose realm claim points to a different realm than the user's
	// realm must be rejected even if signed correctly for that other realm
	forged, err := security.NewJWT(map[string]any{
		core.TokenClaimId:           user.Id,
		core.TokenClaimCollectionId: user.Collection().Id,
		core.TokenClaimType:         core.TokenTypeAuth,
		realms.ClaimRealm:           other.Id,
	}, user.TokenKey()+other.GetString("authSecret"), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	_ = realm
	if _, err := realms.VerifyRealmToken(app, forged); err == nil {
		t.Fatal("expected a token whose realm claim mismatches the user realm to be rejected")
	}
}

func TestRealmTokenAuthenticatesOverHTTP(t *testing.T) {
	app, _, user := setupToken(t)
	defer app.Cleanup()

	token := realmToken(t, app, user)

	pbRouter, err := apis.NewRouter(app)
	if err != nil {
		t.Fatal(err)
	}
	pbRouter.Bind(realms.RealmAuthMiddleware(app))
	pbRouter.GET("/whoami", func(e *core.RequestEvent) error {
		if e.Auth == nil {
			return e.String(401, "anon")
		}
		return e.String(200, e.Auth.Id)
	})
	mux, err := pbRouter.BuildMux()
	if err != nil {
		t.Fatal(err)
	}

	// a valid realm token authenticates as its user
	req := httptest.NewRequest("GET", "/whoami", nil)
	req.Header.Set("Authorization", token)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != 200 || rec.Body.String() != user.Id {
		t.Fatalf("expected realm token to authenticate as %s, got %d %q", user.Id, rec.Code, rec.Body.String())
	}

	// a garbage token does not
	req2 := httptest.NewRequest("GET", "/whoami", nil)
	req2.Header.Set("Authorization", "not.a.valid.token")
	rec2 := httptest.NewRecorder()
	mux.ServeHTTP(rec2, req2)
	if rec2.Code == 200 {
		t.Fatalf("expected a garbage token to not authenticate, got %d %q", rec2.Code, rec2.Body.String())
	}
}

func TestReSignPreservesRefreshable(t *testing.T) {
	app, _, user := setupToken(t)
	defer app.Cleanup()

	// an impersonate-style static (non-refreshable) token must stay
	// non-refreshable after realm re-signing
	staticTok, err := user.NewStaticAuthToken(time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	realmTok, err := realms.ReSignRealmToken(app, user, staticTok)
	if err != nil {
		t.Fatal(err)
	}
	claims, err := security.ParseUnverifiedJWT(realmTok)
	if err != nil {
		t.Fatal(err)
	}
	if r, _ := claims[core.TokenClaimRefreshable].(bool); r {
		t.Fatal("expected a re-signed static token to stay non-refreshable, got refreshable=true")
	}
}

func TestVerifyRealmTokenRejectsNonAuthType(t *testing.T) {
	app, realm, user := setupToken(t)
	defer app.Cleanup()

	// a non-auth token (e.g. verification) carrying a realm claim and signed
	// with the realm secret must still be rejected
	forged, err := security.NewJWT(map[string]any{
		core.TokenClaimId:           user.Id,
		core.TokenClaimCollectionId: user.Collection().Id,
		core.TokenClaimType:         "verification",
		realms.ClaimRealm:           realm.Id,
	}, user.TokenKey()+realm.GetString("authSecret"), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := realms.VerifyRealmToken(app, forged); err == nil {
		t.Fatal("expected a non-auth token to be rejected")
	}
}
