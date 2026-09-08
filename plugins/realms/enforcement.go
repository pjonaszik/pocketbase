package realms

import (
	"fmt"
	"math"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/pocketbase/pocketbase/core"
	"github.com/pocketbase/pocketbase/tools/router"
)

// FieldMaxTokenSeconds is the per-realm maximum auth token lifetime, in seconds.
// A value <= 0 means the realm imposes no ceiling of its own. The effective
// ceiling is always the tightest of the master's and the realm's own value, so
// a child realm can be stricter than the master but can never loosen past it.
const FieldMaxTokenSeconds = "maxTokenSeconds"

// FieldAllowedPermissions is the master realm's permission catalog: the set of
// permission keys that roles in child realms are allowed to grant. An empty
// catalog means no restriction. The master realm is not bound by its own
// catalog. A child realm inherits the catalog and cannot grant outside it.
const FieldAllowedPermissions = "allowedPermissions"

// tokenCeilingSeconds returns the effective token-lifetime ceiling for a realm:
// the tightest positive value among the master realm's policy and the realm's
// own. A return of 0 means no ceiling applies.
func tokenCeilingSeconds(app core.App, realm *core.Record) (int64, error) {
	ceiling := positiveSeconds(realm.GetInt(FieldMaxTokenSeconds))

	master, err := MasterRealm(app)
	if err != nil {
		return 0, err
	}
	ceiling = tightest(ceiling, positiveSeconds(master.GetInt(FieldMaxTokenSeconds)))

	return ceiling, nil
}

// clampTokenExp tightens the token's exp claim so it never outlives the
// effective ceiling. An already-shorter exp is left untouched; the ceiling only
// ever shortens a lifetime, never extends one.
func clampTokenExp(app core.App, realm *core.Record, claims jwt.MapClaims) error {
	ceiling, err := tokenCeilingSeconds(app, realm)
	if err != nil {
		return err
	}
	if ceiling <= 0 {
		return nil
	}

	// compute the deadline in unix seconds directly: multiplying into a
	// time.Duration (nanoseconds) overflows int64 for ceilings above ~9.2e9s and
	// wraps the deadline into the past, which would mint already-expired tokens.
	now := time.Now().Unix()
	if ceiling > math.MaxInt64-now {
		return nil // so large it cannot bind before overflowing: treat as no ceiling
	}
	limit := now + ceiling

	exp, err := claims.GetExpirationTime()
	if err != nil {
		return err
	}
	if exp == nil || limit < exp.Unix() {
		claims["exp"] = limit
	}
	return nil
}

// enforcePermissionCatalog rejects a role whose EFFECTIVE (inheritance-flattened)
// permissions include one outside the master realm's catalog. Checking the
// flattened set, not just the role's own grants, means a role cannot smuggle a
// non-catalog permission in through a parent. The master realm is exempt (it
// defines the catalog), an empty catalog means unrestricted, and a role with no
// effective permissions always passes.
//
// It is applied by roleGuard only when a role's own grants or parents change,
// never on the internal denormalization re-saves the cascade performs, so a
// revoke can still propagate through a subtree that predates a catalog change.
// Tightening the catalog does NOT retroactively revoke permissions already
// granted by roles that predate the change: those roles keep their grants until
// they are next edited (which re-validates them) or removed.
func enforcePermissionCatalog(app core.App, realmID string, effectivePerms []string) error {
	if len(effectivePerms) == 0 {
		return nil
	}

	master, err := MasterRealm(app)
	if err != nil {
		return err
	}
	if realmID == master.Id {
		return nil
	}

	catalog := master.GetStringSlice(FieldAllowedPermissions)
	if len(catalog) == 0 {
		return nil
	}

	allowed := make(map[string]bool, len(catalog))
	for _, p := range catalog {
		allowed[p] = true
	}
	for _, p := range effectivePerms {
		if !allowed[p] {
			return router.NewBadRequestError(fmt.Sprintf("Permission %q is not in the master realm catalog.", p), nil)
		}
	}
	return nil
}

// positiveSeconds treats any non-positive value as "no ceiling" (0).
func positiveSeconds(v int) int64 {
	if v <= 0 {
		return 0
	}
	return int64(v)
}

// tightest returns the smaller of two ceilings, where 0 means "unlimited" and
// therefore loses to any positive ceiling.
func tightest(a, b int64) int64 {
	switch {
	case a == 0:
		return b
	case b == 0:
		return a
	case b < a:
		return b
	default:
		return a
	}
}
