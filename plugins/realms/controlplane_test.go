package realms_test

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/pocketbase/dbx"
	"github.com/pocketbase/pocketbase/apis"
	"github.com/pocketbase/pocketbase/core"
	"github.com/pocketbase/pocketbase/plugins/realms"
	"github.com/pocketbase/pocketbase/tests"
)

func setupControlPlane(t *testing.T) (*tests.TestApp, *core.Record) {
	t.Helper()
	app := setupUsers(t)
	if err := realms.EnsureRBACCollections(app); err != nil {
		t.Fatalf("EnsureRBACCollections: %v", err)
	}
	master, err := realms.MasterRealm(app)
	if err != nil {
		t.Fatalf("MasterRealm: %v", err)
	}
	return app, master
}

func controlMux(t *testing.T, app core.App) http.Handler {
	t.Helper()
	pbRouter, err := apis.NewRouter(app)
	if err != nil {
		t.Fatal(err)
	}
	pbRouter.Bind(realms.RealmAuthMiddleware(app))
	realms.RegisterRealmRoutes(pbRouter, app)
	mux, err := pbRouter.BuildMux()
	if err != nil {
		t.Fatal(err)
	}
	return mux
}

func postRealm(mux http.Handler, token, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest("POST", "/api/realms", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", token)
	}
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	return rec
}

func TestCreateRealmFromMasterWithPermission(t *testing.T) {
	app, master := setupControlPlane(t)
	defer app.Cleanup()

	role := makeRole(t, app, master.Id, "realm-admin", []string{realms.PermissionRealmManage}, nil)
	admin := realmUser(t, app, master.Id, "admin@master", []string{role.Id})
	mux := controlMux(t, app)

	rec := postRealm(mux, realmToken(t, app, admin), `{"slug":"acme","name":"Acme"}`)
	if rec.Code != 200 {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	created, err := app.FindFirstRecordByFilter(realms.CollectionRealms, "slug = 'acme'")
	if err != nil {
		t.Fatalf("realm not created: %v", err)
	}
	if created.GetBool("isMaster") {
		t.Fatal("a created realm must never be master")
	}
	if created.GetString(realms.FieldStatus) != realms.StatusActive {
		t.Fatalf("a created realm must be active, got %q", created.GetString(realms.FieldStatus))
	}
	if len(created.GetString(realms.FieldAuthSecret)) < 30 {
		t.Fatal("a created realm must get its own signing secret")
	}
}

func TestCreatedRealmSecretIsDistinctFromMaster(t *testing.T) {
	app, master := setupControlPlane(t)
	defer app.Cleanup()

	role := makeRole(t, app, master.Id, "realm-admin", []string{realms.PermissionRealmManage}, nil)
	admin := realmUser(t, app, master.Id, "admin@master", []string{role.Id})
	mux := controlMux(t, app)

	if rec := postRealm(mux, realmToken(t, app, admin), `{"slug":"one","name":"One"}`); rec.Code != 200 {
		t.Fatalf("first create: got %d: %s", rec.Code, rec.Body.String())
	}
	if rec := postRealm(mux, realmToken(t, app, admin), `{"slug":"two","name":"Two"}`); rec.Code != 200 {
		t.Fatalf("second create: got %d: %s", rec.Code, rec.Body.String())
	}

	one, _ := app.FindFirstRecordByFilter(realms.CollectionRealms, "slug = 'one'")
	two, _ := app.FindFirstRecordByFilter(realms.CollectionRealms, "slug = 'two'")
	s1, s2 := one.GetString(realms.FieldAuthSecret), two.GetString(realms.FieldAuthSecret)
	if s1 == "" || s1 == s2 || s1 == master.GetString(realms.FieldAuthSecret) {
		t.Fatal("each created realm must get its own unique signing secret")
	}
}

func TestCreateRealmRejectedFromChildRealm(t *testing.T) {
	app, _ := setupControlPlane(t)
	defer app.Cleanup()

	child := newRealm(t, app, "acme")
	role := makeRole(t, app, child.Id, "realm-admin", []string{realms.PermissionRealmManage}, nil)
	u := realmUser(t, app, child.Id, "u@acme", []string{role.Id})
	mux := controlMux(t, app)

	rec := postRealm(mux, realmToken(t, app, u), `{"slug":"evil","name":"Evil"}`)
	if rec.Code != 403 {
		t.Fatalf("a child realm must not manage realms, expected 403, got %d", rec.Code)
	}
	if _, err := app.FindFirstRecordByFilter(realms.CollectionRealms, "slug = 'evil'"); err == nil {
		t.Fatal("no realm must have been created by a child-realm caller")
	}
}

func TestCreateRealmRejectedWithoutPermission(t *testing.T) {
	app, master := setupControlPlane(t)
	defer app.Cleanup()

	u := realmUser(t, app, master.Id, "plain@master", nil)
	mux := controlMux(t, app)

	rec := postRealm(mux, realmToken(t, app, u), `{"slug":"acme","name":"Acme"}`)
	if rec.Code != 403 {
		t.Fatalf("a master user without realm:manage must get 403, got %d", rec.Code)
	}
	if _, err := app.FindFirstRecordByFilter(realms.CollectionRealms, "slug = 'acme'"); err == nil {
		t.Fatal("no realm must have been created without the permission")
	}
}

func TestCreateRealmRejectedAnonymous(t *testing.T) {
	app, _ := setupControlPlane(t)
	defer app.Cleanup()

	mux := controlMux(t, app)
	rec := postRealm(mux, "", `{"slug":"acme","name":"Acme"}`)
	if rec.Code != 401 {
		t.Fatalf("anonymous must get 401, got %d", rec.Code)
	}
}

func TestCreateRealmRejectsDuplicateSlug(t *testing.T) {
	app, master := setupControlPlane(t)
	defer app.Cleanup()

	newRealm(t, app, "acme")
	role := makeRole(t, app, master.Id, "realm-admin", []string{realms.PermissionRealmManage}, nil)
	admin := realmUser(t, app, master.Id, "admin@master", []string{role.Id})
	mux := controlMux(t, app)

	rec := postRealm(mux, realmToken(t, app, admin), `{"slug":"acme","name":"Dup"}`)
	if rec.Code == 200 {
		t.Fatal("a duplicate slug must be rejected")
	}
	n, err := app.CountRecords(realms.CollectionRealms, dbx.HashExp{"slug": "acme"})
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("expected exactly one acme realm, got %d", n)
	}
}
