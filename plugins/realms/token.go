package realms

import (
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/pocketbase/pocketbase/core"
	"github.com/pocketbase/pocketbase/tools/security"
)

// ClaimRealm is the custom JWT claim carrying the user's realm id.
const ClaimRealm = "realm"

// SignRealmToken issues an auth token for the record signed with its realm's
// own secret (record.TokenKey() + realm.authSecret) and carrying the realm
// claim, so the token is cryptographically bound to a single realm.
//
// A record without a realm falls back to the standard PocketBase auth token.
func SignRealmToken(app core.App, record *core.Record) (string, error) {
	realmID := record.GetString(FieldRealm)
	if realmID == "" {
		return record.NewAuthToken()
	}

	realm, err := app.FindRecordById(CollectionRealms, realmID)
	if err != nil {
		return "", err
	}
	secret := realm.GetString("authSecret")

	duration := time.Duration(record.Collection().AuthToken.Duration) * time.Second
	claims := jwt.MapClaims{
		core.TokenClaimType:         core.TokenTypeAuth,
		core.TokenClaimId:           record.Id,
		core.TokenClaimCollectionId: record.Collection().Id,
		core.TokenClaimRefreshable:  true,
		ClaimRealm:                  realmID,
	}

	return security.NewJWT(claims, record.TokenKey()+secret, duration)
}

// VerifyRealmToken validates a realm-signed token and returns the auth record.
// It resolves the realm from the token claim, verifies the HS256 signature with
// the realm's secret, and cross-checks that the token realm matches the user's
// realm. It returns an error for a non-realm token so the caller can fall back
// to the stock verifier.
func VerifyRealmToken(app core.App, token string) (*core.Record, error) {
	claims, err := security.ParseUnverifiedJWT(token)
	if err != nil {
		return nil, err
	}

	realmID, _ := claims[ClaimRealm].(string)
	if realmID == "" {
		return nil, errors.New("not a realm token")
	}
	collectionID, _ := claims[core.TokenClaimCollectionId].(string)
	userID, _ := claims[core.TokenClaimId].(string)
	if collectionID == "" || userID == "" {
		return nil, errors.New("invalid realm token claims")
	}

	realm, err := app.FindRecordById(CollectionRealms, realmID)
	if err != nil {
		return nil, err
	}
	secret := realm.GetString("authSecret")

	user, err := app.FindRecordById(collectionID, userID)
	if err != nil {
		return nil, err
	}

	if _, err := security.ParseJWT(token, user.TokenKey()+secret); err != nil {
		return nil, err
	}

	if user.GetString(FieldRealm) != realmID {
		return nil, errors.New("token realm does not match the user realm")
	}

	return user, nil
}
