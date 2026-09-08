package realms_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/pocketbase/pocketbase/apis"
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

func TestRoleParentChangeCascadesToDescendants(t *testing.T) {
	app, realm := setupRBAC(t)
	defer app.Cleanup()

	parent := makeRole(t, app, realm.Id, "parent", []string{"a", "b"}, nil)
	child := makeRole(t, app, realm.Id, "child", []string{"c"}, []string{parent.Id})
	grandchild := makeRole(t, app, realm.Id, "grandchild", []string{"d"}, []string{child.Id})

	// sanity: grandchild starts with {a,b,c,d}
	if got := reloadRole(t, app, grandchild.Id); !setEq(got, "a", "b", "c", "d") {
		t.Fatalf("precondition: expected {a,b,c,d}, got %v", got)
	}

	// REVOKE permission "b" on the parent
	fresh, err := app.FindRecordById(realms.CollectionRoles, parent.Id)
	if err != nil {
		t.Fatal(err)
	}
	fresh.Set(realms.FieldPermissions, []string{"a"})
	if err := app.Save(fresh); err != nil {
		t.Fatal(err)
	}

	// the revocation must propagate: child -> {a,c}, grandchild -> {a,c,d}
	if got := reloadRole(t, app, child.Id); !setEq(got, "a", "c") {
		t.Fatalf("child allPermissions after revoke: expected {a,c}, got %v", got)
	}
	if got := reloadRole(t, app, grandchild.Id); !setEq(got, "a", "c", "d") {
		t.Fatalf("grandchild allPermissions after revoke: expected {a,c,d}, got %v (fail-open: revoked perm survived)", got)
	}
}

func reloadRole(t *testing.T, app core.App, id string) []string {
	t.Helper()
	r, err := app.FindRecordById(realms.CollectionRoles, id)
	if err != nil {
		t.Fatal(err)
	}
	return r.GetStringSlice(realms.FieldAllPermissions)
}

func TestRoleCascadeDiamond(t *testing.T) {
	app, realm := setupRBAC(t)
	defer app.Cleanup()

	a := makeRole(t, app, realm.Id, "a", []string{"a1"}, nil)
	b := makeRole(t, app, realm.Id, "b", []string{"pb"}, []string{a.Id})
	c := makeRole(t, app, realm.Id, "c", []string{"pc"}, []string{a.Id})
	d := makeRole(t, app, realm.Id, "d", []string{"pd"}, []string{b.Id, c.Id})

	if got := reloadRole(t, app, d.Id); !setEq(got, "a1", "pb", "pc", "pd") {
		t.Fatalf("diamond precondition: expected {a1,pb,pc,pd}, got %v", got)
	}

	// revoke a1 on the shared root
	fresh, err := app.FindRecordById(realms.CollectionRoles, a.Id)
	if err != nil {
		t.Fatal(err)
	}
	fresh.Set(realms.FieldPermissions, []string{})
	if err := app.Save(fresh); err != nil {
		t.Fatal(err)
	}

	if got := reloadRole(t, app, d.Id); !setEq(got, "pb", "pc", "pd") {
		t.Fatalf("diamond after revoke: expected {pb,pc,pd}, got %v", got)
	}
}

func TestRoleCascadeCycleResave(t *testing.T) {
	app, realm := setupRBAC(t)
	defer app.Cleanup()

	a := makeRole(t, app, realm.Id, "a", []string{"pa"}, nil)
	b := makeRole(t, app, realm.Id, "b", []string{"pb"}, []string{a.Id})

	// close the cycle a <-> b
	a2, err := app.FindRecordById(realms.CollectionRoles, a.Id)
	if err != nil {
		t.Fatal(err)
	}
	a2.Set(realms.FieldParents, []string{b.Id})
	if err := app.Save(a2); err != nil {
		t.Fatal(err)
	}

	// add a permission on a; it must propagate into b through the cycle, no hang
	a3, err := app.FindRecordById(realms.CollectionRoles, a.Id)
	if err != nil {
		t.Fatal(err)
	}
	a3.Set(realms.FieldPermissions, []string{"pa", "x"})
	if err := app.Save(a3); err != nil {
		t.Fatalf("re-saving inside a cycle must not hang or error: %v", err)
	}
	if got := reloadRole(t, app, b.Id); !setEq(got, "pa", "pb", "x") {
		t.Fatalf("cycle propagation: expected b={pa,pb,x}, got %v", got)
	}
}

func TestRoleCascadeOnParentDelete(t *testing.T) {
	app, realm := setupRBAC(t)
	defer app.Cleanup()

	gp := makeRole(t, app, realm.Id, "gp", []string{"a"}, nil)
	p := makeRole(t, app, realm.Id, "p", []string{"b"}, []string{gp.Id})
	gc := makeRole(t, app, realm.Id, "gc", []string{"c"}, []string{p.Id})

	if got := reloadRole(t, app, gc.Id); !setEq(got, "a", "b", "c") {
		t.Fatalf("precondition: expected {a,b,c}, got %v", got)
	}

	// deleting the grandparent must drop its permission from descendants
	if err := app.Delete(gp); err != nil {
		t.Fatal(err)
	}
	if got := reloadRole(t, app, p.Id); !setEq(got, "b") {
		t.Fatalf("p after gp delete: expected {b}, got %v", got)
	}
	if got := reloadRole(t, app, gc.Id); !setEq(got, "b", "c") {
		t.Fatalf("gc after gp delete: expected {b,c}, got %v (fail-open: deleted parent perm survived)", got)
	}
}

func TestRoleCascadeMultiChild(t *testing.T) {
	app, realm := setupRBAC(t)
	defer app.Cleanup()

	parent := makeRole(t, app, realm.Id, "parent", []string{"a", "b"}, nil)
	c1 := makeRole(t, app, realm.Id, "c1", []string{"p1"}, []string{parent.Id})
	c2 := makeRole(t, app, realm.Id, "c2", []string{"p2"}, []string{parent.Id})
	c3 := makeRole(t, app, realm.Id, "c3", []string{"p3"}, []string{parent.Id})

	fresh, err := app.FindRecordById(realms.CollectionRoles, parent.Id)
	if err != nil {
		t.Fatal(err)
	}
	fresh.Set(realms.FieldPermissions, []string{"a"}) // revoke b
	if err := app.Save(fresh); err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		id   string
		want []string
	}{
		{c1.Id, []string{"a", "p1"}},
		{c2.Id, []string{"a", "p2"}},
		{c3.Id, []string{"a", "p3"}},
	} {
		if got := reloadRole(t, app, tc.id); !setEq(got, tc.want...) {
			t.Fatalf("multi-child fan-out: role %s expected %v, got %v", tc.id, tc.want, got)
		}
	}
}

func realmUser(t *testing.T, app core.App, realmID, identity string, roleIDs []string) *core.Record {
	t.Helper()
	col, err := app.FindCollectionByNameOrId(realms.CollectionUsers)
	if err != nil {
		t.Fatal(err)
	}
	u := core.NewRecord(col)
	u.Set(realms.FieldRealm, realmID)
	u.Set(realms.FieldIdentity, identity)
	u.SetPassword("password1234")
	if roleIDs != nil {
		u.Set(realms.FieldRoles, roleIDs)
	}
	if err := app.Save(u); err != nil {
		t.Fatalf("save user %q: %v", identity, err)
	}
	return u
}

func TestUserHasPermission(t *testing.T) {
	app, realm := setupRBAC(t)
	defer app.Cleanup()

	base := makeRole(t, app, realm.Id, "base", []string{"posts.read"}, nil)
	writer := makeRole(t, app, realm.Id, "writer", []string{"posts.write"}, []string{base.Id})

	withRole := realmUser(t, app, realm.Id, "w@example.com", []string{writer.Id})
	noRole := realmUser(t, app, realm.Id, "n@example.com", nil)

	// direct permission
	if ok, _ := realms.UserHasPermission(app, withRole, "posts.write"); !ok {
		t.Fatal("expected the writer to have posts.write")
	}
	// inherited permission
	if ok, _ := realms.UserHasPermission(app, withRole, "posts.read"); !ok {
		t.Fatal("expected the writer to inherit posts.read")
	}
	// permission it does not have
	if ok, _ := realms.UserHasPermission(app, withRole, "posts.delete"); ok {
		t.Fatal("did not expect posts.delete")
	}
	// user without roles
	if ok, _ := realms.UserHasPermission(app, noRole, "posts.read"); ok {
		t.Fatal("a user without roles must have no permission")
	}
}

func TestRequirePermissionOverHTTP(t *testing.T) {
	app, realm := setupRBAC(t)
	defer app.Cleanup()

	writer := makeRole(t, app, realm.Id, "writer", []string{"posts.write"}, nil)
	privileged := realmUser(t, app, realm.Id, "priv@example.com", []string{writer.Id})
	plain := realmUser(t, app, realm.Id, "plain@example.com", nil)

	pbRouter, err := apis.NewRouter(app)
	if err != nil {
		t.Fatal(err)
	}
	pbRouter.Bind(realms.RealmAuthMiddleware(app))
	pbRouter.GET("/needs-write", func(e *core.RequestEvent) error {
		return e.String(200, "ok")
	}).Bind(realms.RequirePermission("posts.write"))
	mux, err := pbRouter.BuildMux()
	if err != nil {
		t.Fatal(err)
	}

	call := func(token string) int {
		req := httptest.NewRequest("GET", "/needs-write", nil)
		if token != "" {
			req.Header.Set("Authorization", token)
		}
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		return rec.Code
	}

	if code := call(realmToken(t, app, privileged)); code != 200 {
		t.Fatalf("privileged user: expected 200, got %d", code)
	}
	if code := call(realmToken(t, app, plain)); code != 403 {
		t.Fatalf("user without permission: expected 403, got %d", code)
	}
	if code := call(""); code != 401 {
		t.Fatalf("anonymous: expected 401, got %d", code)
	}
}

func permMux(t *testing.T, app core.App, perm string) http.Handler {
	t.Helper()
	pbRouter, err := apis.NewRouter(app)
	if err != nil {
		t.Fatal(err)
	}
	pbRouter.Bind(realms.RealmAuthMiddleware(app))
	pbRouter.GET("/p", func(e *core.RequestEvent) error {
		return e.String(200, "ok")
	}).Bind(realms.RequirePermission(perm))
	mux, err := pbRouter.BuildMux()
	if err != nil {
		t.Fatal(err)
	}
	return mux
}

func callP(mux http.Handler, token string) int {
	req := httptest.NewRequest("GET", "/p", nil)
	if token != "" {
		req.Header.Set("Authorization", token)
	}
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	return rec.Code
}

func TestUserHasPermissionSkipsDanglingRole(t *testing.T) {
	app, realm := setupRBAC(t)
	defer app.Cleanup()

	valid := makeRole(t, app, realm.Id, "valid", []string{"posts.write"}, nil)
	u := realmUser(t, app, realm.Id, "u@example.com", []string{valid.Id})

	// dangling id before a valid grant: the loop must skip the missing role and
	// still find the permission (set in memory to bypass the write-time guard)
	u.Set(realms.FieldRoles, []string{"nonexistentrole1", valid.Id})
	ok, err := realms.UserHasPermission(app, u, "posts.write")
	if err != nil {
		t.Fatalf("a dangling role must not error: %v", err)
	}
	if !ok {
		t.Fatal("a valid role after a dangling one must still grant the permission")
	}
}

func TestRequirePermissionSuperuserBypasses(t *testing.T) {
	app, _ := setupRBAC(t)
	defer app.Cleanup()

	suCol, err := app.FindCollectionByNameOrId(core.CollectionNameSuperusers)
	if err != nil {
		t.Fatal(err)
	}
	su := core.NewRecord(suCol)
	su.SetEmail("root@example.com")
	su.SetPassword("password1234")
	if err := app.Save(su); err != nil {
		t.Fatal(err)
	}
	token, err := su.NewAuthToken()
	if err != nil {
		t.Fatal(err)
	}

	mux := permMux(t, app, "posts.write")
	if code := callP(mux, token); code != 200 {
		t.Fatalf("a superuser must bypass the permission gate, got %d", code)
	}
}

func TestRequirePermissionIsNotARealmBoundary(t *testing.T) {
	// pins the contract: RequirePermission is a permission gate, not a tenant
	// boundary - users of different realms both pass if each holds the perm
	app, acme := setupRBAC(t)
	defer app.Cleanup()

	beta := newRealm(t, app, "beta")
	acmeRole := makeRole(t, app, acme.Id, "w", []string{"posts.write"}, nil)
	betaRole := makeRole(t, app, beta.Id, "w", []string{"posts.write"}, nil)
	acmeUser := realmUser(t, app, acme.Id, "a@example.com", []string{acmeRole.Id})
	betaUser := realmUser(t, app, beta.Id, "b@example.com", []string{betaRole.Id})

	mux := permMux(t, app, "posts.write")
	if code := callP(mux, realmToken(t, app, acmeUser)); code != 200 {
		t.Fatalf("acme user with the permission: expected 200, got %d", code)
	}
	if code := callP(mux, realmToken(t, app, betaUser)); code != 200 {
		t.Fatalf("beta user with the permission also passes (permission gate, not realm boundary): got %d", code)
	}
}

func TestRequirePermissionEmptyStringDenies(t *testing.T) {
	app, realm := setupRBAC(t)
	defer app.Cleanup()

	role := makeRole(t, app, realm.Id, "w", []string{"posts.write"}, nil)
	u := realmUser(t, app, realm.Id, "u@example.com", []string{role.Id})

	mux := permMux(t, app, "")
	if code := callP(mux, realmToken(t, app, u)); code != 403 {
		t.Fatalf("an empty required permission must deny an authenticated realm user, got %d", code)
	}
}
