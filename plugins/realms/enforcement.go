package realms

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/pocketbase/pocketbase/core"
)

// FieldMaxTokenSeconds is the per-realm maximum auth token lifetime, in seconds.
// A value <= 0 means the realm imposes no ceiling of its own. The effective
// ceiling is always the tightest of the master's and the realm's own value, so
// a child realm can be stricter than the master but can never loosen past it.
const FieldMaxTokenSeconds = "maxTokenSeconds"

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

	limit := time.Now().Add(time.Duration(ceiling) * time.Second).Unix()

	exp, err := claims.GetExpirationTime()
	if err != nil {
		return err
	}
	if exp == nil || limit < exp.Unix() {
		claims["exp"] = limit
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
