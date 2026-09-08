package realms_test

import (
	"testing"

	"github.com/pocketbase/pocketbase/core"
	"github.com/pocketbase/pocketbase/plugins/realms"
	"github.com/pocketbase/pocketbase/tests"
	"github.com/pocketbase/pocketbase/tools/dbutils"
)

func setupUsers(t *testing.T) *tests.TestApp {
	t.Helper()
	app, err := tests.NewTestApp()
	if err != nil {
		t.Fatal(err)
	}
	realms.MustRegister(app)
	if err := realms.EnsureRealmsCollection(app); err != nil {
		t.Fatalf("EnsureRealmsCollection: %v", err)
	}
	if err := realms.EnsureMaster(app); err != nil {
		t.Fatalf("EnsureMaster: %v", err)
	}
	if err := realms.EnsureUsersRealmFields(app); err != nil {
		t.Fatalf("EnsureUsersRealmFields: %v", err)
	}
	return app
}

func newRealm(t *testing.T, app core.App, slug string) *core.Record {
	t.Helper()
	col, err := app.FindCollectionByNameOrId(realms.CollectionRealms)
	if err != nil {
		t.Fatal(err)
	}
	r := core.NewRecord(col)
	r.Set("slug", slug)
	r.Set("name", slug)
	r.Set("isMaster", false)
	r.Set("status", "active")
	r.Set("authSecret", "secret_"+slug+"_0123456789012345678901234567890")
	if err := app.Save(r); err != nil {
		t.Fatalf("create realm %q: %v", slug, err)
	}
	return r
}

func newUser(app core.App, realmID, identity string) error {
	col, err := app.FindCollectionByNameOrId(realms.CollectionUsers)
	if err != nil {
		return err
	}
	u := core.NewRecord(col)
	u.Set(realms.FieldRealm, realmID)
	u.Set(realms.FieldIdentity, identity)
	u.SetPassword("password1234")
	return app.Save(u)
}

func TestSameIdentityAllowedAcrossRealms(t *testing.T) {
	app := setupUsers(t)
	defer app.Cleanup()

	acme := newRealm(t, app, "acme")
	beta := newRealm(t, app, "beta")

	if err := newUser(app, acme.Id, "bob@example.com"); err != nil {
		t.Fatalf("first user in acme: %v", err)
	}
	if err := newUser(app, beta.Id, "bob@example.com"); err != nil {
		t.Fatalf("same identity in a different realm must be allowed: %v", err)
	}
}

func TestSameIdentitySameRealmRejected(t *testing.T) {
	app := setupUsers(t)
	defer app.Cleanup()

	acme := newRealm(t, app, "acme")

	if err := newUser(app, acme.Id, "bob@example.com"); err != nil {
		t.Fatalf("first user: %v", err)
	}
	if err := newUser(app, acme.Id, "bob@example.com"); err == nil {
		t.Fatal("expected a duplicate (realm, identity) to be rejected, got nil error")
	}
}

func TestUserRequiresRealm(t *testing.T) {
	app := setupUsers(t)
	defer app.Cleanup()

	col, err := app.FindCollectionByNameOrId(realms.CollectionUsers)
	if err != nil {
		t.Fatal(err)
	}
	u := core.NewRecord(col)
	u.Set(realms.FieldIdentity, "no-realm@example.com")
	u.SetPassword("password1234")
	if err := app.Save(u); err == nil {
		t.Fatal("expected a user without a realm to be rejected, got nil error")
	}
}

func TestBootstrapWiresRealmLayer(t *testing.T) {
	app, err := tests.NewTestApp()
	if err != nil {
		t.Fatal(err)
	}
	defer app.Cleanup()

	// Register binds the OnBootstrap handlers; NewTestApp already bootstrapped,
	// so re-run bootstrap to fire them end-to-end.
	realms.MustRegister(app)
	app.ResetBootstrapState()
	if err := app.Bootstrap(); err != nil {
		t.Fatal(err)
	}

	// the realms collection and master must exist
	if _, err := app.FindFirstRecordByFilter(realms.CollectionRealms, "isMaster = true"); err != nil {
		t.Fatalf("bootstrap did not seed the master realm: %v", err)
	}

	// and the users collection must have gained the realm layer
	users, err := app.FindCollectionByNameOrId(realms.CollectionUsers)
	if err != nil {
		t.Fatal(err)
	}
	if users.Fields.GetByName(realms.FieldRealm) == nil {
		t.Fatal("bootstrap did not wire the realm field onto the users collection")
	}
	if users.Fields.GetByName(realms.FieldIdentity) == nil {
		t.Fatal("bootstrap did not wire the identity field onto the users collection")
	}
}

func TestEnsureUsersRealmFieldsIdempotent(t *testing.T) {
	app := setupUsers(t)
	defer app.Cleanup()

	// second call must be a no-op that keeps a single index and a valid collection
	if err := realms.EnsureUsersRealmFields(app); err != nil {
		t.Fatalf("second EnsureUsersRealmFields: %v", err)
	}
	users, err := app.FindCollectionByNameOrId(realms.CollectionUsers)
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, idx := range users.Indexes {
		if dbutils.ParseIndex(idx).IndexName == "idx_users_realm_identity" {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("expected exactly one idx_users_realm_identity, got %d", count)
	}
	if err := app.Validate(users); err != nil {
		t.Fatalf("users collection must stay valid after a repeated call: %v", err)
	}
}

func TestUserRequiresIdentity(t *testing.T) {
	app := setupUsers(t)
	defer app.Cleanup()

	acme := newRealm(t, app, "acme")
	col, err := app.FindCollectionByNameOrId(realms.CollectionUsers)
	if err != nil {
		t.Fatal(err)
	}
	u := core.NewRecord(col)
	u.Set(realms.FieldRealm, acme.Id)
	u.SetPassword("password1234")
	if err := app.Save(u); err == nil {
		t.Fatal("expected a realm user without an identity to be rejected, got nil error")
	}
}

func TestLegacyBlankUsersDoNotCollide(t *testing.T) {
	app := setupUsers(t)
	defer app.Cleanup()

	// pre-existing (migration-time) rows with blank realm+identity must be
	// exempt from the partial unique index; simulate two of them via SaveNoValidate
	col, err := app.FindCollectionByNameOrId(realms.CollectionUsers)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		u := core.NewRecord(col)
		u.SetPassword("password1234")
		if err := app.SaveNoValidate(u); err != nil {
			t.Fatalf("legacy blank user %d must not collide on the partial index: %v", i, err)
		}
	}
}
