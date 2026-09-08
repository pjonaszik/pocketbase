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

	// read the persisted column back, not the in-memory record, since API rules
	// match on the stored allPermissions
	fresh, err := app.FindRecordById(realms.CollectionRoles, child.Id)
	if err != nil {
		t.Fatal(err)
	}
	got := fresh.GetStringSlice(realms.FieldAllPermissions)
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

	fresh, err := app.FindRecordById(realms.CollectionRoles, c.Id)
	if err != nil {
		t.Fatal(err)
	}
	got := fresh.GetStringSlice(realms.FieldAllPermissions)
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

func TestRoleRealmIsImmutable(t *testing.T) {
	app, acme := setupRBAC(t)
	defer app.Cleanup()

	beta := newRealm(t, app, "beta")
	role := makeRole(t, app, acme.Id, "admin", []string{"a"}, nil)

	// reload before mutating, as the API does on update
	reloaded, err := app.FindRecordById(realms.CollectionRoles, role.Id)
	if err != nil {
		t.Fatal(err)
	}
	reloaded.Set(realms.FieldRealm, beta.Id)
	if err := app.Save(reloaded); err == nil {
		t.Fatal("expected a role's realm to be immutable after creation")
	}
}

func TestRoleCycleIsSafe(t *testing.T) {
	app, realm := setupRBAC(t)
	defer app.Cleanup()

	a := makeRole(t, app, realm.Id, "a", []string{"pa"}, nil)
	b := makeRole(t, app, realm.Id, "b", []string{"pb"}, []string{a.Id})

	// close the cycle: a's parent becomes b (a -> b -> a)
	a.Set(realms.FieldParents, []string{b.Id})
	if err := app.Save(a); err != nil {
		t.Fatalf("a cyclic parent graph must not hang or error: %v", err)
	}

	fresh, err := app.FindRecordById(realms.CollectionRoles, a.Id)
	if err != nil {
		t.Fatal(err)
	}
	got := fresh.GetStringSlice(realms.FieldAllPermissions)
	if !setEq(got, "pa", "pb") {
		t.Fatalf("cycle allPermissions must be finite {pa,pb}, got %v", got)
	}
}

func TestUserMultipleRolesSameRealm(t *testing.T) {
	app, realm := setupRBAC(t)
	defer app.Cleanup()

	r1 := makeRole(t, app, realm.Id, "r1", []string{"p1"}, nil)
	r2 := makeRole(t, app, realm.Id, "r2", []string{"p2"}, nil)

	col, err := app.FindCollectionByNameOrId(realms.CollectionUsers)
	if err != nil {
		t.Fatal(err)
	}
	u := core.NewRecord(col)
	u.Set(realms.FieldRealm, realm.Id)
	u.Set(realms.FieldIdentity, "bob@example.com")
	u.SetPassword("password1234")
	u.Set(realms.FieldRoles, []string{r1.Id, r2.Id})
	if err := app.Save(u); err != nil {
		t.Fatalf("assigning two same-realm roles must succeed: %v", err)
	}
}

func TestEnsureRBACCollectionsIdempotent(t *testing.T) {
	app, _ := setupRBAC(t)
	defer app.Cleanup()

	if err := realms.EnsureRBACCollections(app); err != nil {
		t.Fatalf("second EnsureRBACCollections must be a no-op: %v", err)
	}
	roles, err := app.FindCollectionByNameOrId(realms.CollectionRoles)
	if err != nil {
		t.Fatal(err)
	}
	if roles.Fields.GetByName(realms.FieldParents) == nil {
		t.Fatal("parents self-relation must survive a re-run")
	}
}
