// Package realms adds Keycloak-style realms on top of PocketBase: a single
// immutable "master" realm seeded at bootstrap, from which other realms are
// created. This is the foundation increment (collection + master seed +
// master immutability); per-realm identity, RBAC and the policy ceiling build
// on it.
package realms

import (
	"database/sql"
	"errors"
	"strings"

	"github.com/pocketbase/dbx"
	"github.com/pocketbase/pocketbase/apis"
	"github.com/pocketbase/pocketbase/core"
	"github.com/pocketbase/pocketbase/tools/hook"
	"github.com/pocketbase/pocketbase/tools/security"
)

// CollectionRealms is the name of the realms collection.
const CollectionRealms = "realms"

// MasterSlug is the stable slug of the unique master realm.
const MasterSlug = "master"

// FieldAuthSecret is the per-realm token signing secret field.
const FieldAuthSecret = "authSecret"

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
		if err := EnsureMaster(e.App); err != nil {
			return err
		}
		return EnsureUsersRealmFields(e.App)
	})

	bindRealmTokens(app)
	bindRealmLogin(app)

	return nil
}

// bindRealmTokens wires the per-realm token issuance and verification: a realm
// user's auth token is re-signed with its realm secret at issuance, and a
// middleware verifies realm tokens before the stock loadAuthToken (which no-ops
// once e.Auth is set). Non-realm users and superusers keep the stock behavior.
func bindRealmTokens(app core.App) {
	app.OnRecordAuthRequest(CollectionUsers).BindFunc(func(e *core.RecordAuthRequestEvent) error {
		if e.Record != nil && e.Record.GetString(FieldRealm) != "" {
			tok, err := ReSignRealmToken(e.App, e.Record, e.Token)
			if err != nil {
				return err
			}
			e.Token = tok
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
		&core.SelectField{Name: "status", Values: []string{"active", "disabled"}, MaxSelect: 1, Required: true},
		&core.TextField{Name: FieldAuthSecret, Required: true, Hidden: true, Min: 30},
	)
	col.AddIndex("idx_realms_slug", true, "slug", "")

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
	r.Set("status", "active")
	r.Set(FieldAuthSecret, security.RandomString(50))

	return app.Save(r)
}

// bindMasterGuards installs the model-level guards that keep the master realm
// immutable and unique. They run on every persistence path (API, superuser,
// internal saves), so a realm admin cannot bypass them.
func bindMasterGuards(app core.App) {
	app.OnRecordDelete(CollectionRealms).BindFunc(func(e *core.RecordEvent) error {
		if e.Record.GetBool("isMaster") {
			return errors.New("the master realm cannot be deleted")
		}
		return e.Next()
	})

	app.OnRecordUpdate(CollectionRealms).BindFunc(func(e *core.RecordEvent) error {
		original := e.Record.Original()
		if original.GetBool("isMaster") {
			if e.Record.GetString("status") != "active" {
				return errors.New("the master realm status is immutable and must stay active")
			}
			if !e.Record.GetBool("isMaster") {
				return errors.New("the master realm cannot be demoted")
			}
			if e.Record.GetString("slug") != original.GetString("slug") {
				return errors.New("the master realm slug is immutable")
			}
			if e.Record.GetString(FieldAuthSecret) != original.GetString(FieldAuthSecret) {
				return errors.New("the master realm authSecret is immutable")
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
				return errors.New("only one master realm is allowed")
			}
		}
		return e.Next()
	}
	app.OnRecordCreate(CollectionRealms).BindFunc(guardSingleMaster)
	app.OnRecordUpdate(CollectionRealms).BindFunc(guardSingleMaster)
}
