package realms_test

import (
	"strings"
	"testing"

	"github.com/pocketbase/dbx"
	"github.com/pocketbase/pocketbase/core"
	"github.com/pocketbase/pocketbase/plugins/realms"
	"github.com/pocketbase/pocketbase/tests"
)

func setup(t *testing.T) *tests.TestApp {
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
	return app
}

func master(t *testing.T, app core.App) *core.Record {
	t.Helper()
	r, err := app.FindFirstRecordByFilter(realms.CollectionRealms, "isMaster = true")
	if err != nil {
		t.Fatalf("master not found: %v", err)
	}
	return r
}

func TestEnsureMasterSeedsSingleMaster(t *testing.T) {
	app := setup(t)
	defer app.Cleanup()

	// idempotent: a second call must not create a duplicate
	if err := realms.EnsureMaster(app); err != nil {
		t.Fatalf("second EnsureMaster: %v", err)
	}

	got, err := app.FindAllRecords(realms.CollectionRealms, dbx.HashExp{"isMaster": true})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("expected exactly 1 master realm, got %d", len(got))
	}
	m := got[0]
	if m.GetString("slug") != realms.MasterSlug {
		t.Fatalf("expected master slug %q, got %q", realms.MasterSlug, m.GetString("slug"))
	}
	if len(m.GetString("authSecret")) < 30 {
		t.Fatalf("expected a generated authSecret (>=30 chars), got %q", m.GetString("authSecret"))
	}
	if m.GetString("status") != "active" {
		t.Fatalf("expected master status active, got %q", m.GetString("status"))
	}
}

func TestMasterCannotBeDeleted(t *testing.T) {
	app := setup(t)
	defer app.Cleanup()

	if err := app.Delete(master(t, app)); err == nil {
		t.Fatal("expected the master realm delete to be blocked, got nil error")
	}
	// still there
	if _, err := app.FindFirstRecordByFilter(realms.CollectionRealms, "isMaster = true"); err != nil {
		t.Fatalf("master must survive a blocked delete: %v", err)
	}
}

func TestMasterCannotBeDisabled(t *testing.T) {
	app := setup(t)
	defer app.Cleanup()

	m := master(t, app)
	m.Set("status", "disabled")
	if err := app.Save(m); err == nil {
		t.Fatal("expected disabling the master realm to be blocked, got nil error")
	}
}

func TestMasterCannotBeDemoted(t *testing.T) {
	app := setup(t)
	defer app.Cleanup()

	m := master(t, app)
	m.Set("isMaster", false)
	if err := app.Save(m); err == nil {
		t.Fatal("expected demoting the master realm to be blocked, got nil error")
	}
}

func TestCannotCreateSecondMaster(t *testing.T) {
	app := setup(t)
	defer app.Cleanup()

	col, err := app.FindCollectionByNameOrId(realms.CollectionRealms)
	if err != nil {
		t.Fatal(err)
	}
	r := core.NewRecord(col)
	r.Set("slug", "master2")
	r.Set("name", "Second master")
	r.Set("isMaster", true)
	r.Set("status", "active")
	r.Set("authSecret", strings.Repeat("x", 40))
	if err := app.Save(r); err == nil {
		t.Fatal("expected creating a second master realm to be blocked, got nil error")
	}
}

func TestChildRealmCanBeCreatedAndDeleted(t *testing.T) {
	app := setup(t)
	defer app.Cleanup()

	col, err := app.FindCollectionByNameOrId(realms.CollectionRealms)
	if err != nil {
		t.Fatal(err)
	}
	r := core.NewRecord(col)
	r.Set("slug", "acme")
	r.Set("name", "Acme")
	r.Set("isMaster", false)
	r.Set("status", "active")
	r.Set("authSecret", strings.Repeat("y", 40))
	if err := app.Save(r); err != nil {
		t.Fatalf("a normal child realm must be creatable: %v", err)
	}
	if err := app.Delete(r); err != nil {
		t.Fatalf("a normal child realm must be deletable: %v", err)
	}
}

func TestMasterStatusIsPinnedToActive(t *testing.T) {
	app := setup(t)
	defer app.Cleanup()

	m := master(t, app)
	m.Set("status", "")
	if err := app.Save(m); err == nil {
		t.Fatal("expected an empty master status to be rejected, got nil error")
	}

	m2 := master(t, app)
	m2.Set("status", "banned")
	if err := app.SaveNoValidate(m2); err == nil {
		t.Fatal("expected an arbitrary master status to be rejected even via SaveNoValidate, got nil error")
	}

	fresh := master(t, app)
	if fresh.GetString("status") != "active" {
		t.Fatalf("master status must remain active, got %q", fresh.GetString("status"))
	}
}

func TestCannotPromoteChildToMaster(t *testing.T) {
	app := setup(t)
	defer app.Cleanup()

	col, err := app.FindCollectionByNameOrId(realms.CollectionRealms)
	if err != nil {
		t.Fatal(err)
	}
	child := core.NewRecord(col)
	child.Set("slug", "beta")
	child.Set("name", "Beta")
	child.Set("isMaster", false)
	child.Set("status", "active")
	child.Set("authSecret", strings.Repeat("z", 40))
	if err := app.Save(child); err != nil {
		t.Fatal(err)
	}

	child.Set("isMaster", true)
	if err := app.Save(child); err == nil {
		t.Fatal("expected promoting a child realm to master to be blocked, got nil error")
	}
}

func TestMasterSlugIsImmutable(t *testing.T) {
	app := setup(t)
	defer app.Cleanup()

	m := master(t, app)
	m.Set("slug", "renamed")
	if err := app.Save(m); err == nil {
		t.Fatal("expected the master slug to be immutable, got nil error")
	}
}

func TestMasterAuthSecretIsImmutable(t *testing.T) {
	app := setup(t)
	defer app.Cleanup()

	m := master(t, app)
	m.Set("authSecret", strings.Repeat("q", 40))
	if err := app.Save(m); err == nil {
		t.Fatal("expected the master authSecret to be immutable, got nil error")
	}
}
