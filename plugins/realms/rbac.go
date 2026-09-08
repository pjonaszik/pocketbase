package realms

import (
	"errors"
	"sort"

	"github.com/pocketbase/dbx"
	"github.com/pocketbase/pocketbase/core"
	"github.com/pocketbase/pocketbase/tools/hook"
	"github.com/pocketbase/pocketbase/tools/list"
)

// RBAC collections and fields.
const (
	CollectionRoles     = "roles"
	FieldKey            = "key"
	FieldParents        = "parents"
	FieldPermissions    = "permissions"
	FieldAllPermissions = "allPermissions"
	FieldRoles          = "roles" // on the users collection
)

// EnsureRBACCollections creates the roles collection and adds the roles relation
// to the users collection. Idempotent.
func EnsureRBACCollections(app core.App) error {
	realmsCol, err := app.FindCollectionByNameOrId(CollectionRealms)
	if err != nil {
		return err
	}

	roles, err := app.FindCollectionByNameOrId(CollectionRoles)
	if err != nil {
		roles = core.NewBaseCollection(CollectionRoles)
		roles.Fields.Add(
			&core.RelationField{Name: FieldRealm, CollectionId: realmsCol.Id, Required: true, MaxSelect: 1},
			&core.TextField{Name: FieldKey, Required: true},
			&core.TextField{Name: "name"},
			&core.JSONField{Name: FieldPermissions, MaxSize: 100000},
			&core.JSONField{Name: FieldAllPermissions, MaxSize: 200000},
		)
		if err := app.Save(roles); err != nil {
			return err
		}
		roles, err = app.FindCollectionByNameOrId(CollectionRoles)
		if err != nil {
			return err
		}
	}

	// ensure the self-relation parents + the unique index exist (self-repairing
	// on re-run even if a previous partial creation left them out)
	rolesChanged := false
	if roles.Fields.GetByName(FieldParents) == nil {
		roles.Fields.Add(&core.RelationField{Name: FieldParents, CollectionId: roles.Id, MaxSelect: 999})
		rolesChanged = true
	}
	if !hasIndex(roles, "idx_roles_realm_key") {
		roles.AddIndex("idx_roles_realm_key", true, "realm, key", "")
		rolesChanged = true
	}
	if rolesChanged {
		if err := app.Save(roles); err != nil {
			return err
		}
	}

	users, err := app.FindCollectionByNameOrId(CollectionUsers)
	if err != nil {
		return err
	}
	if users.Fields.GetByName(FieldRoles) == nil {
		users.Fields.Add(&core.RelationField{Name: FieldRoles, CollectionId: roles.Id, MaxSelect: 999})
		return app.Save(users)
	}

	return nil
}

// computeAllPermissions returns a role's own permissions unioned with all of its
// ancestors' permissions, flattened. The visited set guards against cycles.
func computeAllPermissions(app core.App, role *core.Record, visited map[string]bool) []string {
	if visited[role.Id] {
		return nil
	}
	visited[role.Id] = true

	set := map[string]bool{}
	for _, p := range role.GetStringSlice(FieldPermissions) {
		set[p] = true
	}
	for _, parentID := range role.GetStringSlice(FieldParents) {
		parent, err := app.FindRecordById(CollectionRoles, parentID)
		if err != nil {
			continue
		}
		for _, p := range computeAllPermissions(app, parent, visited) {
			set[p] = true
		}
	}

	out := make([]string, 0, len(set))
	for p := range set {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

// bindRBAC installs the role denormalization and realm-scoping guards.
func bindRBAC(app core.App) {
	roleGuard := func(e *core.RecordEvent) error {
		realmID := e.Record.GetString(FieldRealm)
		if original := e.Record.Original(); original.GetString(FieldRealm) != "" &&
			realmID != original.GetString(FieldRealm) {
			return errors.New("a role's realm is immutable")
		}
		for _, parentID := range e.Record.GetStringSlice(FieldParents) {
			parent, err := e.App.FindRecordById(CollectionRoles, parentID)
			if err != nil {
				return err
			}
			if parent.GetString(FieldRealm) != realmID {
				return errors.New("a role parent must belong to the same realm")
			}
		}
		e.Record.Set(FieldAllPermissions, computeAllPermissions(e.App, e.Record, map[string]bool{}))
		return e.Next()
	}
	app.OnRecordCreate(CollectionRoles).BindFunc(roleGuard)
	app.OnRecordUpdate(CollectionRoles).BindFunc(roleGuard)

	userRolesGuard := func(e *core.RecordEvent) error {
		realmID := e.Record.GetString(FieldRealm)
		if realmID == "" {
			return e.Next()
		}
		for _, roleID := range e.Record.GetStringSlice(FieldRoles) {
			role, err := e.App.FindRecordById(CollectionRoles, roleID)
			if err != nil {
				return err
			}
			if role.GetString(FieldRealm) != realmID {
				return errors.New("a user role must belong to the user's realm")
			}
		}
		return e.Next()
	}
	app.OnRecordCreate(CollectionUsers).BindFunc(userRolesGuard)
	app.OnRecordUpdate(CollectionUsers).BindFunc(userRolesGuard)

	// cascade: when a role changes, re-flatten its direct children so a
	// permission revoked on a parent propagates to descendants.
	//
	// Termination is by fixpoint, not monotonicity (a revoke shrinks the set):
	// computeAllPermissions reads only `permissions` and `parents`, never
	// `allPermissions`, so during one cascade the dependency graph is frozen;
	// each node has a single correct value, is set to it the first time it is
	// recomputed, then compares equal and is never re-saved. Re-saves are thus
	// bounded by the node count, and cycles/diamonds terminate.
	//
	// Note: the cascade is not atomic with the triggering update - each child
	// Save is its own operation, so a mid-cascade failure can leave later
	// descendants stale (over-privilege) while the parent save reports an error;
	// a retry re-runs the idempotent cascade and heals it. Acceptable at the
	// admin-managed role scale this targets.
	app.OnRecordAfterUpdateSuccess(CollectionRoles).BindFunc(func(e *core.RecordEvent) error {
		if err := e.Next(); err != nil {
			return err
		}

		changed := e.Record
		realmRoles, err := e.App.FindAllRecords(CollectionRoles, dbx.HashExp{FieldRealm: changed.GetString(FieldRealm)})
		if err != nil {
			return err
		}

		for _, child := range realmRoles {
			if child.Id == changed.Id {
				continue
			}
			if !list.ExistInSlice(changed.Id, child.GetStringSlice(FieldParents)) {
				continue
			}
			next := computeAllPermissions(e.App, child, map[string]bool{})
			if !sameStringSet(child.GetStringSlice(FieldAllPermissions), next) {
				// re-save triggers roleGuard (re-flatten) and this cascade for
				// the grandchildren; the change-guard above stops it converging
				if err := e.App.Save(child); err != nil {
					return err
				}
			}
		}

		return nil
	})
}

func sameStringSet(a, b []string) bool {
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

// UserHasPermission reports whether any of the user's roles grants the given
// permission (via the denormalized, inheritance-flattened allPermissions).
func UserHasPermission(app core.App, user *core.Record, permission string) (bool, error) {
	for _, roleID := range user.GetStringSlice(FieldRoles) {
		role, err := app.FindRecordById(CollectionRoles, roleID)
		if err != nil {
			continue // a dangling role reference grants nothing
		}
		if list.ExistInSlice(permission, role.GetStringSlice(FieldAllPermissions)) {
			return true, nil
		}
	}
	return false, nil
}

// RequirePermission is a route middleware that allows the request only when the
// authenticated record holds the given permission through its realm roles.
func RequirePermission(permission string) *hook.Handler[*core.RequestEvent] {
	return &hook.Handler[*core.RequestEvent]{
		Func: func(e *core.RequestEvent) error {
			if e.Auth == nil {
				return e.UnauthorizedError("The request requires a valid authorization token.", nil)
			}
			ok, err := UserHasPermission(e.App, e.Auth, permission)
			if err != nil {
				return err
			}
			if !ok {
				return e.ForbiddenError("You do not have the required permission.", nil)
			}
			return e.Next()
		},
	}
}
