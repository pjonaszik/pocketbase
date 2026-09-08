package realms

import (
	"errors"
	"sort"

	"github.com/pocketbase/pocketbase/core"
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

	if _, err := app.FindCollectionByNameOrId(CollectionRoles); err != nil {
		roles := core.NewBaseCollection(CollectionRoles)
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
		// self-relation parents must be added after the collection exists
		roles, err = app.FindCollectionByNameOrId(CollectionRoles)
		if err != nil {
			return err
		}
		roles.Fields.Add(&core.RelationField{Name: FieldParents, CollectionId: roles.Id, MaxSelect: 999})
		roles.AddIndex("idx_roles_realm_key", true, "realm, key", "")
		if err := app.Save(roles); err != nil {
			return err
		}
	}

	users, err := app.FindCollectionByNameOrId(CollectionUsers)
	if err != nil {
		return err
	}
	if users.Fields.GetByName(FieldRoles) == nil {
		roles, err := app.FindCollectionByNameOrId(CollectionRoles)
		if err != nil {
			return err
		}
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
}
