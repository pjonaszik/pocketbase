package realms

import (
	"errors"

	"github.com/golang-jwt/jwt/v5"
	"github.com/pocketbase/pocketbase/core"
	"github.com/pocketbase/pocketbase/tools/security"
)

// ClaimRealm is the custom JWT claim carrying the user's realm id.
const ClaimRealm = "realm"

// ReSignRealmToken re-signs a stock-issued auth token with the user's realm
// secret and a realm claim. A non-realm user or a non-auth token is returned
// unchanged.
func ReSignRealmToken(app core.App, record *core.Record, stockToken string) (string, error) {
	realmID := record.GetString(FieldRealm)
	if realmID == "" {
		return stockToken, nil
	}

	// preserve the stock token's claims (type, exp, refreshable, ...) so that
	// re-signing does not change token semantics; only auth tokens are re-signed
	claims, err := security.ParseUnverifiedJWT(stockToken)
	if err != nil {
		return "", err
	}
	if t, _ := claims[core.TokenClaimType].(string); t != core.TokenTypeAuth {
		return stockToken, nil
	}

	realm, err := app.FindRecordById(CollectionRealms, realmID)
	if err != nil {
		return "", err
	}
	secret := realm.GetString(FieldAuthSecret)

	key := record.TokenKey() + secret
	if key == "" {
		return "", errors.New("realm token signing key is empty")
	}

	if err := clampTokenExp(app, realm, claims); err != nil {
		return "", err
	}

	claims[ClaimRealm] = realmID
	return jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(key))
}

// VerifyRealmToken validates a realm-signed auth token and returns the auth
// record. It rejects non-auth token types, resolves the realm from the claim,
// verifies the HS256 signature with the realm secret, asserts the record lives
// in the users collection, and cross-checks the token realm against the user's.
func VerifyRealmToken(app core.App, token string) (*core.Record, error) {
	claims, err := security.ParseUnverifiedJWT(token)
	if err != nil {
		return nil, err
	}
	if t, _ := claims[core.TokenClaimType].(string); t != core.TokenTypeAuth {
		return nil, errors.New("not an auth token")
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
	secret := realm.GetString(FieldAuthSecret)

	user, err := app.FindRecordById(collectionID, userID)
	if err != nil {
		return nil, err
	}
	if user.Collection().Name != CollectionUsers {
		return nil, errors.New("realm token collection mismatch")
	}

	if _, err := security.ParseJWT(token, user.TokenKey()+secret); err != nil {
		return nil, err
	}

	if user.GetString(FieldRealm) != realmID {
		return nil, errors.New("token realm does not match the user realm")
	}

	return user, nil
}
