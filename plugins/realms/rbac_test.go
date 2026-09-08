package realms_test

import (
	"testing"

	"github.com/pocketbase/pocketbase/core"
	"github.com/pocketbase/pocketbase/plugins/realms"
	"github.com/pocketbase/pocketbase/tests"
)

func setupRBAC(t *testing.T) (*tests.TestApp, *core.Record) {
	t.Helper()
	app := setupUsers(t)
	if err := realms.EnsureRBACCollections(app); err != nil {
		t.Fatalf("EnsureRBACCollections: %v", err)
	}
	realm := newRealm(t, app, "acme")
	return app, realm
}

func makeRole(t *testing.T, app core.App, realmID, key string, perms []string, parents []string) *core.Record {
	t.Helper()
	col, err := app.FindCollectionByNameOrId(realms.CollectionRoles)
	if err != nil {
		t.Fatal(err)
	}
	r := core.NewRecord(col)
	r.Set(realms.FieldRealm, realmID)
	r.Set(realms.FieldKey, key)
	r.Set(realms.FieldPermissions, perms)
	if parents != nil {
		r.Set(realms.FieldParents, parents)
	}
	if err := app.Save(r); err != nil {
		t.Fatalf("save role %q: %v", key, err)
	}
	return r
}

func setEq(a []string, b ...string) bool {
	if len(a) != len(b) {
		return false
	}
	m := map[string]bool{}
	for _, x := range a {
		m[x] = true
	}
	for _, x := range b {
		if !m[x] {
			return false
		}
	}
	return true
}

func TestRoleAllPermissionsFlattensInheritance(t *testing.T) {
	app, realm := setupRBAC(t)
	defer app.Cleanup()

	parent := makeRole(t, app, realm.Id, "parent", []string{"posts.read"}, nil)
	child := makeRole(t, app, realm.Id, "child", []string{"posts.write"}, []string{parent.Id})

	got := child.GetStringSlice(realms.FieldAllPermissions)
	if !setEq(got, "posts.read", "posts.write") {
		t.Fatalf("expected child.allPermissions {posts.read, posts.write}, got %v", got)
	}
}

func TestRoleInheritanceMultiLevel(t *testing.T) {
	app, realm := setupRBAC(t)
	defer app.Cleanup()

	gp := makeRole(t, app, realm.Id, "grandparent", []string{"a"}, nil)
	p := makeRole(t, app, realm.Id, "parent", []string{"b"}, []string{gp.Id})
	c := makeRole(t, app, realm.Id, "child", []string{"c"}, []string{p.Id})

	got := c.GetStringSlice(realms.FieldAllPermissions)
	if !setEq(got, "a", "b", "c") {
		t.Fatalf("expected child.allPermissions {a,b,c}, got %v", got)
	}
}

func TestRoleParentsMustMatchRealm(t *testing.T) {
	app, acme := setupRBAC(t)
	defer app.Cleanup()

	beta := newRealm(t, app, "beta")
	betaRole := makeRole(t, app, beta.Id, "betarole", []string{"x"}, nil)

	col, _ := app.FindCollectionByNameOrId(realms.CollectionRoles)
	r := core.NewRecord(col)
	r.Set(realms.FieldRealm, acme.Id)
	r.Set(realms.FieldKey, "acmerole")
	r.Set(realms.FieldPermissions, []string{"y"})
	r.Set(realms.FieldParents, []string{betaRole.Id}) // parent from another realm
	if err := app.Save(r); err == nil {
		t.Fatal("expected a role with a cross-realm parent to be rejected")
	}
}

func TestUserRolesMustMatchRealm(t *testing.T) {
	app, acme := setupRBAC(t)
	defer app.Cleanup()

	beta := newRealm(t, app, "beta")
	betaRole := makeRole(t, app, beta.Id, "betarole", []string{"x"}, nil)

	col, _ := app.FindCollectionByNameOrId(realms.CollectionUsers)
	u := core.NewRecord(col)
	u.Set(realms.FieldRealm, acme.Id)
	u.Set(realms.FieldIdentity, "bob@example.com")
	u.SetPassword("password1234")
	u.Set(realms.FieldRoles, []string{betaRole.Id}) // role from another realm
	if err := app.Save(u); err == nil {
		t.Fatal("expected assigning a cross-realm role to a user to be rejected")
	}
}
