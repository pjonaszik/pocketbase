// Package realms adds Keycloak-style realms on top of PocketBase, entirely in
// userland with no core changes: a single immutable "master" realm seeded at
// bootstrap, from which child realms are provisioned. It layers per-realm
// identity isolation and token signing, realm-scoped login, per-realm RBAC with
// inheritance and cascading revocation, a control plane to create realms from
// the master, and a master policy ceiling (token lifetime and permission
// catalog) that child realms inherit and cannot loosen.
package realms

import (
	"database/sql"
	"errors"
	"strings"

	"github.com/pocketbase/dbx"
	"github.com/pocketbase/pocketbase/apis"
	"github.com/pocketbase/pocketbase/core"
	"github.com/pocketbase/pocketbase/tools/hook"
	"github.com/pocketbase/pocketbase/tools/router"
	"github.com/pocketbase/pocketbase/tools/security"
	"github.com/pocketbase/pocketbase/tools/types"
)

// CollectionRealms is the name of the realms collection.
const CollectionRealms = "realms"

// MasterSlug is the stable slug of the unique master realm.
const MasterSlug = "master"

// FieldAuthSecret is the per-realm token signing secret field.
const FieldAuthSecret = "authSecret"

// FieldStatus and the realm status values.
const (
	FieldStatus    = "status"
	StatusActive   = "active"
	StatusDisabled = "disabled"
)

// MustRegister is like Register but panics on error.
func MustRegister(app core.App) {
	if err := Register(app); err != nil {
		panic(err)
	}
}

// Register wires the realms plugin into the app: it installs the
// master-immutability guards and ensures the realms collection and the master
// realm exist once the app is bootstrapped.
func Register(app core.App) error {
	bindMasterGuards(app)

	app.OnBootstrap().BindFunc(func(e *core.BootstrapEvent) error {
		if err := e.Next(); err != nil {
			return err
		}
		if err := EnsureRealmsCollection(e.App); err != nil {
			return err
		}
		if err := EnsureEnforcementFields(e.App); err != nil {
			return err
		}
		if err := EnsureMaster(e.App); err != nil {
			return err
		}
		if err := EnsureUsersRealmFields(e.App); err != nil {
			return err
		}
		return EnsureRBACCollections(e.App)
	})

	bindRealmTokens(app)
	bindRealmLogin(app)
	bindRBAC(app)
	bindControlPlane(app)

	return nil
}

// bindRealmTokens wires the per-realm token issuance and verification: a realm
// user's auth token is re-signed with its realm secret at issuance, and a
// middleware verifies realm tokens before the stock loadAuthToken (which no-ops
// once e.Auth is set). Non-realm users and superusers keep the stock behavior.
func bindRealmTokens(app core.App) {
	app.OnRecordAuthRequest(CollectionUsers).BindFunc(func(e *core.RecordAuthRequestEvent) error {
		if e.Record != nil {
			if realmID := e.Record.GetString(FieldRealm); realmID != "" {
				realm, err := e.App.FindRecordById(CollectionRealms, realmID)
				if err != nil {
					return err
				}
				// gate every login path: the realm must be active
				if realm.GetString(FieldStatus) != StatusActive {
					return e.ForbiddenError("The realm is not active.", nil)
				}
				// gate: an explicit realm param must match the account realm,
				// so a realm login form cannot be tricked into another realm
				if reqRealm := e.Request.URL.Query().Get("realm"); reqRealm != "" && reqRealm != realm.GetString("slug") {
					return e.ForbiddenError("The requested realm does not match the account realm.", nil)
				}
				tok, err := ReSignRealmToken(e.App, e.Record, e.Token)
				if err != nil {
					return err
				}
				e.Token = tok
			}
		}
		return e.Next()
	})

	app.OnServe().BindFunc(func(e *core.ServeEvent) error {
		e.Router.Bind(RealmAuthMiddleware(e.App))
		return e.Next()
	})
}

// RealmAuthMiddleware authenticates a realm-signed bearer token and sets e.Auth
// before the stock loadAuthToken (which no-ops once e.Auth is set). Non-realm
// tokens and superusers fall through to the stock verifier untouched.
func RealmAuthMiddleware(app core.App) *hook.Handler[*core.RequestEvent] {
	return &hook.Handler[*core.RequestEvent]{
		Id:       "realmsLoadAuthToken",
		Priority: apis.DefaultLoadAuthTokenMiddlewarePriority - 1,
		Func: func(e *core.RequestEvent) error {
			if e.Auth == nil {
				if token := realmBearerToken(e); token != "" {
					if user, err := VerifyRealmToken(e.App, token); err == nil {
						e.Auth = user
					}
				}
			}
			return e.Next()
		},
	}
}

func realmBearerToken(e *core.RequestEvent) string {
	token := e.Request.Header.Get("Authorization")
	if len(token) > 7 && strings.EqualFold(token[:7], "Bearer ") {
		return token[7:]
	}
	return token
}

// EnsureRealmsCollection creates the realms collection if it does not exist yet.
// It is idempotent.
func EnsureRealmsCollection(app core.App) error {
	_, err := app.FindCollectionByNameOrId(CollectionRealms)
	if err == nil {
		return nil // already exists
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return err // surface real errors instead of masking them behind a create attempt
	}

	col := core.NewBaseCollection(CollectionRealms)
	col.Fields.Add(
		&core.TextField{Name: "slug", Required: true},
		&core.TextField{Name: "name"},
		&core.BoolField{Name: "isMaster"},
		&core.SelectField{Name: "status", Values: []string{StatusActive, StatusDisabled}, MaxSelect: 1, Required: true},
		&core.TextField{Name: FieldAuthSecret, Required: true, Hidden: true, Min: 30},
		&core.NumberField{Name: FieldMaxTokenSeconds, OnlyInt: true, Min: types.Pointer(0.0)},
		&core.JSONField{Name: FieldAllowedPermissions, MaxSize: 100000},
	)
	col.AddIndex("idx_realms_slug", true, "slug", "")

	return app.Save(col)
}

// EnsureEnforcementFields adds the master-enforcement policy fields to an
// existing realms collection. It is idempotent and self-repairing so a realm
// store created before these fields existed gains them without a destructive
// schema reset.
func EnsureEnforcementFields(app core.App) error {
	col, err := app.FindCollectionByNameOrId(CollectionRealms)
	if err != nil {
		return err
	}
	missing := false
	if col.Fields.GetByName(FieldMaxTokenSeconds) == nil {
		col.Fields.Add(&core.NumberField{Name: FieldMaxTokenSeconds, OnlyInt: true, Min: types.Pointer(0.0)})
		missing = true
	}
	if col.Fields.GetByName(FieldAllowedPermissions) == nil {
		col.Fields.Add(&core.JSONField{Name: FieldAllowedPermissions, MaxSize: 100000})
		missing = true
	}
	if !missing {
		return nil
	}
	return app.Save(col)
}

// EnsureMaster seeds the unique master realm if none exists yet. It is idempotent.
func EnsureMaster(app core.App) error {
	count, err := app.CountRecords(CollectionRealms, dbx.HashExp{"isMaster": true})
	if err != nil {
		return err
	}
	if count > 0 {
		return nil
	}

	col, err := app.FindCollectionByNameOrId(CollectionRealms)
	if err != nil {
		return err
	}

	r := core.NewRecord(col)
	r.Set("slug", MasterSlug)
	r.Set("name", "Master")
	r.Set("isMaster", true)
	r.Set(FieldStatus, StatusActive)
	r.Set(FieldAuthSecret, security.RandomString(50))

	return app.Save(r)
}

// bindMasterGuards installs the model-level guards that keep the master realm
// immutable and unique. They run on every persistence path (API, superuser,
// internal saves), so a realm admin cannot bypass them.
func bindMasterGuards(app core.App) {
	app.OnRecordDelete(CollectionRealms).BindFunc(func(e *core.RecordEvent) error {
		if e.Record.GetBool("isMaster") {
			return router.NewBadRequestError("The master realm cannot be deleted.", nil)
		}
		return e.Next()
	})

	app.OnRecordUpdate(CollectionRealms).BindFunc(func(e *core.RecordEvent) error {
		original := e.Record.Original()
		if original.GetBool("isMaster") {
			if e.Record.GetString(FieldStatus) != StatusActive {
				return router.NewBadRequestError("The master realm status is immutable and must stay active.", nil)
			}
			if !e.Record.GetBool("isMaster") {
				return router.NewBadRequestError("The master realm cannot be demoted.", nil)
			}
			if e.Record.GetString("slug") != original.GetString("slug") {
				return router.NewBadRequestError("The master realm slug is immutable.", nil)
			}
			if e.Record.GetString(FieldAuthSecret) != original.GetString(FieldAuthSecret) {
				return router.NewBadRequestError("The master realm signing secret is immutable.", nil)
			}
		}
		return e.Next()
	})

	guardSingleMaster := func(e *core.RecordEvent) error {
		if e.Record.GetBool("isMaster") {
			others, err := e.App.CountRecords(CollectionRealms, dbx.NewExp(
				"isMaster = true AND id != {:id}",
				dbx.Params{"id": e.Record.Id},
			))
			if err != nil {
				return err
			}
			if others > 0 {
				return router.NewBadRequestError("Only one master realm is allowed.", nil)
			}
		}
		return e.Next()
	}
	app.OnRecordCreate(CollectionRealms).BindFunc(guardSingleMaster)
	app.OnRecordUpdate(CollectionRealms).BindFunc(guardSingleMaster)
}
