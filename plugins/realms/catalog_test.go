package realms_test

import (
	"testing"

	"github.com/pocketbase/pocketbase/core"
	"github.com/pocketbase/pocketbase/plugins/realms"
)

func setCatalog(t *testing.T, app core.App, perms []string) {
	t.Helper()
	master, err := realms.MasterRealm(app)
	if err != nil {
		t.Fatalf("master realm: %v", err)
	}
	master.Set(realms.FieldAllowedPermissions, perms)
	if err := app.Save(master); err != nil {
		t.Fatalf("set catalog: %v", err)
	}
}

func tryMakeRole(app core.App, realmID, key string, perms []string) error {
	col, err := app.FindCollectionByNameOrId(realms.CollectionRoles)
	if err != nil {
		return err
	}
	r := core.NewRecord(col)
	r.Set(realms.FieldRealm, realmID)
	r.Set(realms.FieldKey, key)
	r.Set(realms.FieldPermissions, perms)
	return app.Save(r)
}

func TestNoCatalogAllowsAnyChildPermission(t *testing.T) {
	app, realm := setupRBAC(t)
	defer app.Cleanup()

	// empty catalog means unrestricted
	if err := tryMakeRole(app, realm.Id, "editor", []string{"posts.write", "billing.admin"}); err != nil {
		t.Fatalf("with no catalog a child role may grant anything: %v", err)
	}
}

func TestCatalogRejectsPermissionOutsideIt(t *testing.T) {
	app, realm := setupRBAC(t)
	defer app.Cleanup()

	setCatalog(t, app, []string{"posts.read"})

	if err := tryMakeRole(app, realm.Id, "editor", []string{"posts.write"}); err == nil {
		t.Fatal("a child role must not grant a permission outside the master catalog")
	}
}

func TestCatalogAllowsPermissionInsideIt(t *testing.T) {
	app, realm := setupRBAC(t)
	defer app.Cleanup()

	setCatalog(t, app, []string{"posts.read", "posts.write"})

	if err := tryMakeRole(app, realm.Id, "editor", []string{"posts.read"}); err != nil {
		t.Fatalf("a permission inside the catalog must be allowed: %v", err)
	}
}

func TestMasterRealmIsExemptFromCatalog(t *testing.T) {
	app, _ := setupRBAC(t)
	defer app.Cleanup()

	setCatalog(t, app, []string{"posts.read"})

	master, err := realms.MasterRealm(app)
	if err != nil {
		t.Fatal(err)
	}
	// the master defines the catalog and is not bound by it
	if err := tryMakeRole(app, master.Id, "root", []string{"billing.admin", "realm:manage"}); err != nil {
		t.Fatalf("the master realm must be exempt from its own catalog: %v", err)
	}
}

func TestCatalogEnforcedOnUpdate(t *testing.T) {
	app, realm := setupRBAC(t)
	defer app.Cleanup()

	setCatalog(t, app, []string{"posts.read"})

	role := makeRole(t, app, realm.Id, "editor", []string{"posts.read"}, nil)
	role.Set(realms.FieldPermissions, []string{"posts.read", "billing.admin"})
	if err := app.Save(role); err == nil {
		t.Fatal("a child role must not be updated to grant a permission outside the catalog")
	}
}

func TestCatalogIgnoresEmptyPermissionList(t *testing.T) {
	app, realm := setupRBAC(t)
	defer app.Cleanup()

	setCatalog(t, app, []string{"posts.read"})

	if err := tryMakeRole(app, realm.Id, "empty", nil); err != nil {
		t.Fatalf("a role granting nothing must be allowed under any catalog: %v", err)
	}
}
