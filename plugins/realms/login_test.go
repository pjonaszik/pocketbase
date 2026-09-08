package realms_test

import (
	"encoding/json/v2"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/pocketbase/pocketbase/apis"
	"github.com/pocketbase/pocketbase/core"
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

func loginMux(t *testing.T, app core.App) *httptest.Server {
	t.Helper()
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
	return httptest.NewServer(mux)
}

func loginCode(t *testing.T, srv *httptest.Server, identity, password, realmParam string) int {
	t.Helper()
	u := srv.URL + "/api/collections/users/auth-with-password"
	if realmParam != "" {
		u += "?" + url.Values{"realm": {realmParam}}.Encode()
	}
	body := `{"identity":` + jsonString(identity) + `,"password":` + jsonString(password) + `}`
	req, err := httpNewPost(u, body)
	if err != nil {
		t.Fatal(err)
	}
	res, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	return res.StatusCode
}

func TestDisabledRealmBlocksLoginViaUsername(t *testing.T) {
	app, realm, user := setupToken(t)
	defer app.Cleanup()

	// the auto-generated username is a realm-unscoped login path
	username := user.GetString("username")
	if username == "" {
		t.Fatal("expected the user to have an auto username")
	}

	srv := loginMux(t, app)
	defer srv.Close()

	// while active, username login works
	if code := loginCode(t, srv, username, "password1234", ""); code != 200 {
		t.Fatalf("active realm: expected username login 200, got %d", code)
	}

	// disable the realm; username login must now be blocked on every path
	realm.Set("status", "disabled")
	if err := app.Save(realm); err != nil {
		t.Fatal(err)
	}
	if code := loginCode(t, srv, username, "password1234", ""); code == 200 {
		t.Fatal("disabled realm: expected username login to be blocked, got 200")
	}
}

func TestRealmParamMustMatchUserRealm(t *testing.T) {
	app, _, _ := setupToken(t) // seeds realm "acme" + a user
	defer app.Cleanup()

	// a user in realm "beta" WITH a native email (a stock-lookup path)
	beta := newRealm(t, app, "beta")
	col, err := app.FindCollectionByNameOrId(realms.CollectionUsers)
	if err != nil {
		t.Fatal(err)
	}
	u := core.NewRecord(col)
	u.Set(realms.FieldRealm, beta.Id)
	u.Set(realms.FieldIdentity, "carol@example.com")
	u.Set("email", "carol@example.com")
	u.SetPassword("password1234")
	if err := app.Save(u); err != nil {
		t.Fatal(err)
	}

	srv := loginMux(t, app)
	defer srv.Close()

	// submitting ?realm=acme for a beta user must be rejected, not silently
	// authenticated as beta via the email path
	if code := loginCode(t, srv, "carol@example.com", "password1234", "acme"); code == 200 {
		t.Fatal("realm mismatch: expected rejection, got 200 (authenticated in the wrong realm)")
	}
	// and the correct realm still works
	if code := loginCode(t, srv, "carol@example.com", "password1234", "beta"); code != 200 {
		t.Fatalf("matching realm: expected 200, got %d", code)
	}
}

func httpNewPost(u, body string) (*http.Request, error) {
	req, err := http.NewRequest("POST", u, strings.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	return req, nil
}

func jsonString(v string) string {
	b, _ := json.Marshal(v)
	return string(b)
}
