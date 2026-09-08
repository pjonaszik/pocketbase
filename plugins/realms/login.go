package realms

import (
	"github.com/pocketbase/dbx"
	"github.com/pocketbase/pocketbase/core"
)

// FindRealmUserByIdentity resolves an active realm's user by realm slug and
// identity. It returns sql.ErrNoRows (via the query) when nothing matches.
func FindRealmUserByIdentity(app core.App, realmSlug, identity string) (*core.Record, error) {
	realm, err := app.FindFirstRecordByFilter(
		CollectionRealms,
		"slug = {:slug} && status = 'active'",
		dbx.Params{"slug": realmSlug},
	)
	if err != nil {
		return nil, err
	}

	return app.FindFirstRecordByFilter(
		CollectionUsers,
		"realm = {:realm} && identity = {:identity}",
		dbx.Params{"realm": realm.Id, "identity": identity},
	)
}

// bindRealmLogin scopes password login by realm: when the stock identity lookup
// (email) finds nothing and the request carries a `realm` query param, the user
// is resolved by (realm, identity) instead. If nothing matches, e.Record stays
// nil and the stock handler performs its dummy password check, so no
// enumeration side-channel is introduced.
func bindRealmLogin(app core.App) {
	app.OnRecordAuthWithPasswordRequest(CollectionUsers).BindFunc(func(e *core.RecordAuthWithPasswordRequestEvent) error {
		if e.Record == nil {
			if realmSlug := e.Request.URL.Query().Get("realm"); realmSlug != "" {
				if user, err := FindRealmUserByIdentity(e.App, realmSlug, e.Identity); err == nil {
					e.Record = user
				}
			}
		}
		return e.Next()
	})
}
