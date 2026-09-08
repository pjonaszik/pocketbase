package realms_test

import (
	"encoding/json/v2"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/pocketbase/pocketbase/apis"
	"github.com/pocketbase/pocketbase/plugins/realms"
)

func TestFindRealmUserByIdentity(t *testing.T) {
	app, realm, user := setupToken(t)
	defer app.Cleanup()

	got, err := realms.FindRealmUserByIdentity(app, realm.GetString("slug"), "bob@example.com")
	if err != nil {
		t.Fatalf("FindRealmUserByIdentity: %v", err)
	}
	if got == nil || got.Id != user.Id {
		t.Fatalf("expected to resolve user %s, got %v", user.Id, got)
	}

	// wrong realm slug must not resolve the user
	if _, err := realms.FindRealmUserByIdentity(app, "nope", "bob@example.com"); err == nil {
		t.Fatal("expected no user for an unknown realm")
	}
}

func TestRealmPasswordLoginEndToEnd(t *testing.T) {
	app, realm, user := setupToken(t)
	defer app.Cleanup()

	// MFA is orthogonal to realm-scoped login (it belongs to the policy-ceiling
	// increment); disable it on the users collection so this test exercises the
	// login lookup and token issuance in isolation.
	usersCol, err := app.FindCollectionByNameOrId(realms.CollectionUsers)
	if err != nil {
		t.Fatal(err)
	}
	usersCol.MFA.Enabled = false
	if err := app.Save(usersCol); err != nil {
		t.Fatal(err)
	}

	pbRouter, err := apis.NewRouter(app)
	if err != nil {
		t.Fatal(err)
	}
	mux, err := pbRouter.BuildMux()
	if err != nil {
		t.Fatal(err)
	}

	body := `{"identity":"bob@example.com","password":"password1234"}`
	req := httptest.NewRequest("POST", "/api/collections/users/auth-with-password?"+url.Values{"realm": {realm.GetString("slug")}}.Encode(), strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != 200 {
		t.Fatalf("expected realm-scoped password login to succeed, got %d: %s", rec.Code, rec.Body.String())
	}
	// the issued token must be a realm token resolving to our user
	if !strings.Contains(rec.Body.String(), `"token"`) {
		t.Fatalf("expected a token in the response, got %s", rec.Body.String())
	}
	// extract token and verify it is realm-signed
	var resp struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	authed, err := realms.VerifyRealmToken(app, resp.Token)
	if err != nil {
		t.Fatalf("login must return a realm-signed token: %v", err)
	}
	if authed.Id != user.Id {
		t.Fatalf("token must resolve to %s, got %s", user.Id, authed.Id)
	}
}
