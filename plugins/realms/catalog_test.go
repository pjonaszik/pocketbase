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
	return tryMakeRoleWithParents(app, realmID, key, perms, nil)
}

func tryMakeRoleWithParents(app core.App, realmID, key string, perms, parents []string) error {
	col, err := app.FindCollectionByNameOrId(realms.CollectionRoles)
	if err != nil {
		return err
	}
	r := core.NewRecord(col)
	r.Set(realms.FieldRealm, realmID)
	r.Set(realms.FieldKey, key)
	r.Set(realms.FieldPermissions, perms)
	if parents != nil {
		r.Set(realms.FieldParents, parents)
	}
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

func TestChildRoleCannotInheritNonCatalogPermission(t *testing.T) {
	app, realm := setupRBAC(t)
	defer app.Cleanup()

	// legacy role minted while the catalog is still empty (grandfathered)
	legacy := makeRole(t, app, realm.Id, "legacy", []string{"realm:manage"}, nil)

	// operator later locks the catalog down
	setCatalog(t, app, []string{"posts.read"})

	// a new role whose OWN perms are catalog-clean but which inherits realm:manage
	// from the grandfathered parent must be rejected: its effective (flattened)
	// permission set escapes the catalog
	err := tryMakeRoleWithParents(app, realm.Id, "sneaky", []string{"posts.read"}, []string{legacy.Id})
	if err == nil {
		t.Fatal("a child role must not inherit a permission outside the master catalog")
	}
}

func TestCatalogTighteningDoesNotBreakCascade(t *testing.T) {
	app, realm := setupRBAC(t)
	defer app.Cleanup()

	// built while the catalog is empty
	parent := makeRole(t, app, realm.Id, "parent", []string{"a"}, nil)
	child := makeRole(t, app, realm.Id, "child", []string{"billing.admin"}, []string{parent.Id})

	// operator tightens the catalog; the existing roles are grandfathered
	setCatalog(t, app, []string{"a", "b"})

	// a legitimate parent update (its own perms stay within the catalog) must not
	// be blocked by the grandfathered child, and the cascade must still re-flatten
	parent.Set(realms.FieldPermissions, []string{"a", "b"})
	if err := app.Save(parent); err != nil {
		t.Fatalf("a legal parent update must not be blocked by a grandfathered child: %v", err)
	}
	if got := reloadRole(t, app, child.Id); !setEq(got, "a", "b", "billing.admin") {
		t.Fatalf("the cascade must re-flatten the child to [a b billing.admin], got %v", got)
	}
}

func TestCatalogTighteningDoesNotRetroactivelyStrip(t *testing.T) {
	app, realm := setupRBAC(t)
	defer app.Cleanup()

	legacy := makeRole(t, app, realm.Id, "legacy", []string{"realm:manage"}, nil)
	setCatalog(t, app, []string{"posts.read"})

	// tightening the catalog does not rewrite roles that predate it; the grant
	// persists until the role is next edited or removed (honest policy semantics)
	if got := reloadRole(t, app, legacy.Id); !setEq(got, "realm:manage") {
		t.Fatalf("a grandfathered role must keep its permission until edited, got %v", got)
	}
}
