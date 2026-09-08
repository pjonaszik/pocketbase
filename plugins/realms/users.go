package realms

import (
	"strings"

	"github.com/pocketbase/pocketbase/core"
	"github.com/pocketbase/pocketbase/tools/dbutils"
)

// CollectionUsers is the default auth collection realm users live in.
const CollectionUsers = "users"

// FieldRealm is the relation field scoping a user to its realm.
const FieldRealm = "realm"

// FieldIdentity is the realm-scoped login identity (the native email is left blank).
const FieldIdentity = "identity"

// EnsureUsersRealmFields adds the realm relation and identity fields to the
// users collection and makes the native email optional so realm users can leave
// it blank. Idempotent.
func EnsureUsersRealmFields(app core.App) error {
	users, err := app.FindCollectionByNameOrId(CollectionUsers)
	if err != nil {
		return err
	}

	realmsCol, err := app.FindCollectionByNameOrId(CollectionRealms)
	if err != nil {
		return err
	}

	changed := false

	if users.Fields.GetByName(FieldRealm) == nil {
		users.Fields.Add(&core.RelationField{
			Name:         FieldRealm,
			CollectionId: realmsCol.Id,
			Required:     true,
			MaxSelect:    1,
		})
		changed = true
	}

	if users.Fields.GetByName(FieldIdentity) == nil {
		users.Fields.Add(&core.TextField{Name: FieldIdentity, Required: true})
		changed = true
	}

	if emailField, ok := users.Fields.GetByName(core.FieldNameEmail).(*core.EmailField); ok && emailField.Required {
		emailField.Required = false
		changed = true
	}

	// realm-scoped identity uniqueness: the same identity may exist in
	// different realms, never twice within the same realm
	const identityIndex = "idx_users_realm_identity"
	if !hasIndex(users, identityIndex) {
		users.AddIndex(identityIndex, true, "realm, identity", "realm != '' AND identity != ''")
		changed = true
	}

	if !changed {
		return nil
	}
	return app.Save(users)
}

func hasIndex(col *core.Collection, name string) bool {
	for _, idx := range col.Indexes {
		if parsed := dbutils.ParseIndex(idx); strings.EqualFold(parsed.IndexName, name) {
			return true
		}
	}
	return false
}
