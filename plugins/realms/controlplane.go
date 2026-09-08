package realms

import (
	"net/http"

	"github.com/pocketbase/pocketbase/core"
	"github.com/pocketbase/pocketbase/tools/hook"
	"github.com/pocketbase/pocketbase/tools/router"
	"github.com/pocketbase/pocketbase/tools/security"
)

// PermissionRealmManage is the permission required to manage realms from the master.
const PermissionRealmManage = "realm:manage"

// MasterRealm returns the unique master realm record.
func MasterRealm(app core.App) (*core.Record, error) {
	return app.FindFirstRecordByFilter(CollectionRealms, "isMaster = true")
}

// RequireMasterRealm is a route middleware that allows only a caller
// authenticated in the master realm (or a superuser). It is the realm-binding
// gate the control plane relies on: management of realms is a master-only act.
func RequireMasterRealm(app core.App) *hook.Handler[*core.RequestEvent] {
	return &hook.Handler[*core.RequestEvent]{
		Func: func(e *core.RequestEvent) error {
			if e.Auth == nil {
				return e.UnauthorizedError("The request requires a valid authorization token.", nil)
			}
			if e.Auth.IsSuperuser() {
				return e.Next()
			}
			master, err := MasterRealm(e.App)
			if err != nil {
				return err
			}
			if e.Auth.GetString(FieldRealm) != master.Id {
				return e.ForbiddenError("Only the master realm may manage realms.", nil)
			}
			return e.Next()
		},
	}
}

// RegisterRealmRoutes installs the realm management endpoints onto the router.
// It is called from OnServe and is exported so the same wiring can be exercised
// under test.
func RegisterRealmRoutes(r *router.Router[*core.RequestEvent], app core.App) {
	r.POST("/api/realms", createRealmHandler).
		Bind(RequireMasterRealm(app), RequirePermission(PermissionRealmManage))
}

// createRealmHandler provisions a new child realm. The caller has already been
// proven to sit in the master realm and to hold realm:manage; here the record
// invariants are pinned: never master, always active, always its own secret.
func createRealmHandler(e *core.RequestEvent) error {
	form := struct {
		Slug string `json:"slug"`
		Name string `json:"name"`
	}{}
	if err := e.BindBody(&form); err != nil {
		return e.BadRequestError("Failed to read the realm data.", err)
	}
	if form.Slug == "" {
		return e.BadRequestError("A realm slug is required.", nil)
	}

	col, err := e.App.FindCollectionByNameOrId(CollectionRealms)
	if err != nil {
		return err
	}

	realm := core.NewRecord(col)
	realm.Set("slug", form.Slug)
	realm.Set("name", form.Name)
	realm.Set("isMaster", false)
	realm.Set(FieldStatus, StatusActive)
	realm.Set(FieldAuthSecret, security.RandomString(50))

	if err := e.App.Save(realm); err != nil {
		return e.BadRequestError("Failed to create the realm.", err)
	}

	return e.JSON(http.StatusOK, map[string]any{
		"id":   realm.Id,
		"slug": realm.GetString("slug"),
		"name": realm.GetString("name"),
	})
}

// bindControlPlane registers the realm management routes on serve.
func bindControlPlane(app core.App) {
	app.OnServe().BindFunc(func(e *core.ServeEvent) error {
		RegisterRealmRoutes(e.Router, e.App)
		return e.Next()
	})
}
