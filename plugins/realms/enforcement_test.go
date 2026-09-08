package realms_test

import (
	"testing"
	"time"

	"github.com/pocketbase/pocketbase/core"
	"github.com/pocketbase/pocketbase/plugins/realms"
	"github.com/pocketbase/pocketbase/tools/security"
)

func tokenTTL(t *testing.T, token string) int64 {
	t.Helper()
	claims, err := security.ParseUnverifiedJWT(token)
	if err != nil {
		t.Fatalf("parse token: %v", err)
	}
	exp, err := claims.GetExpirationTime()
	if err != nil || exp == nil {
		t.Fatalf("token must carry an exp: %v", err)
	}
	return exp.Unix() - time.Now().Unix()
}

func setCeiling(t *testing.T, app core.App, realm *core.Record, seconds int) {
	t.Helper()
	realm.Set(realms.FieldMaxTokenSeconds, seconds)
	if err := app.Save(realm); err != nil {
		t.Fatalf("set ceiling: %v", err)
	}
}

func setMasterCeiling(t *testing.T, app core.App, seconds int) {
	t.Helper()
	master, err := realms.MasterRealm(app)
	if err != nil {
		t.Fatalf("master realm: %v", err)
	}
	setCeiling(t, app, master, seconds)
}

func masterUser(t *testing.T, app core.App, identity string) *core.Record {
	t.Helper()
	master, err := realms.MasterRealm(app)
	if err != nil {
		t.Fatalf("master realm: %v", err)
	}
	col, err := app.FindCollectionByNameOrId(realms.CollectionUsers)
	if err != nil {
		t.Fatal(err)
	}
	u := core.NewRecord(col)
	u.Set(realms.FieldRealm, master.Id)
	u.Set(realms.FieldIdentity, identity)
	u.SetPassword("password1234")
	if err := app.Save(u); err != nil {
		t.Fatal(err)
	}
	return u
}

func assertTTLNear(t *testing.T, ttl int64, want int64) {
	t.Helper()
	if ttl < want-5 || ttl > want+5 {
		t.Fatalf("expected a token lifetime near %ds, got %ds", want, ttl)
	}
}

func TestRealmTokenUncappedByDefault(t *testing.T) {
	app, _, user := setupToken(t)
	defer app.Cleanup()

	// with no ceiling anywhere, the token keeps the collection default lifetime,
	// which is far longer than any ceiling exercised below
	if ttl := tokenTTL(t, realmToken(t, app, user)); ttl < 3600 {
		t.Fatalf("an uncapped realm token must keep the long collection lifetime, got %ds", ttl)
	}
}

func TestMasterCeilingCapsChildTokens(t *testing.T) {
	app, _, user := setupToken(t)
	defer app.Cleanup()

	setMasterCeiling(t, app, 120)

	assertTTLNear(t, tokenTTL(t, realmToken(t, app, user)), 120)
}

func TestChildRealmMayBeStricterThanMaster(t *testing.T) {
	app, realm, user := setupToken(t)
	defer app.Cleanup()

	setMasterCeiling(t, app, 600)
	setCeiling(t, app, realm, 120)

	assertTTLNear(t, tokenTTL(t, realmToken(t, app, user)), 120)
}

func TestChildRealmCannotLoosenPastMaster(t *testing.T) {
	app, realm, user := setupToken(t)
	defer app.Cleanup()

	setMasterCeiling(t, app, 120)
	setCeiling(t, app, realm, 600)

	// the child asked for 600s but the master ceiling of 120s must win
	assertTTLNear(t, tokenTTL(t, realmToken(t, app, user)), 120)
}

func TestMasterOwnTokensAreCapped(t *testing.T) {
	app, _, _ := setupToken(t)
	defer app.Cleanup()

	setMasterCeiling(t, app, 120)
	admin := masterUser(t, app, "admin@master")

	assertTTLNear(t, tokenTTL(t, realmToken(t, app, admin)), 120)
}

func TestLargeCeilingDoesNotOverflowToInstantExpiry(t *testing.T) {
	app, _, user := setupToken(t)
	defer app.Cleanup()

	// ~1000 years: a plausible "effectively unlimited" value an admin may type
	// instead of the documented 0. Naive duration arithmetic (seconds * 1e9 ns)
	// overflows int64 and wraps the deadline into the past, minting an already
	// expired token for the whole subtree. A large ceiling must never shorten a
	// token below its normal lifetime.
	setMasterCeiling(t, app, 31536000000)

	if ttl := tokenTTL(t, realmToken(t, app, user)); ttl <= 0 {
		t.Fatalf("a very large ceiling must not overflow into an expired token, got ttl=%ds", ttl)
	}
}
