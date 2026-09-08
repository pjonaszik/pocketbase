package realms_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/pocketbase/pocketbase/plugins/realms"
	"github.com/pocketbase/pocketbase/tools/router"
)

// asApiError mirrors what the CRUD handlers do (firstApiError -> errors.As): a
// guard's rejection must carry a *router.ApiError so its reason reaches the
// client instead of the generic "Failed to create/delete record" wrapper.
func asApiError(t *testing.T, err error) *router.ApiError {
	t.Helper()
	if err == nil {
		t.Fatal("expected a rejection, got nil")
	}
	var apiErr *router.ApiError
	if !errors.As(err, &apiErr) {
		t.Fatalf("rejection must surface as a router.ApiError, got %T: %v", err, err)
	}
	return apiErr
}

func TestMasterDeleteSurfacesReason(t *testing.T) {
	app, _ := setupRBAC(t)
	defer app.Cleanup()

	master, err := realms.MasterRealm(app)
	if err != nil {
		t.Fatal(err)
	}
	apiErr := asApiError(t, app.Delete(master))
	if apiErr.Status != 400 {
		t.Fatalf("status: got %d, want 400", apiErr.Status)
	}
	if !strings.Contains(strings.ToLower(apiErr.Message), "master") {
		t.Fatalf("message must explain the master realm cannot be deleted, got %q", apiErr.Message)
	}
}

func TestCatalogViolationSurfacesReason(t *testing.T) {
	app, realm := setupRBAC(t)
	defer app.Cleanup()

	setCatalog(t, app, []string{"posts.read"})

	apiErr := asApiError(t, tryMakeRole(app, realm.Id, "finance", []string{"billing.admin"}))
	if !strings.Contains(strings.ToLower(apiErr.Message), "catalog") {
		t.Fatalf("message must name the catalog, got %q", apiErr.Message)
	}
}

func TestRoleParentCrossRealmSurfacesReason(t *testing.T) {
	app, realm := setupRBAC(t)
	defer app.Cleanup()

	other := newRealm(t, app, "other")
	otherRole := makeRole(t, app, other.Id, "x", []string{"a"}, nil)

	apiErr := asApiError(t, tryMakeRoleWithParents(app, realm.Id, "y", nil, []string{otherRole.Id}))
	if !strings.Contains(strings.ToLower(apiErr.Message), "realm") {
		t.Fatalf("message must explain the cross-realm parent, got %q", apiErr.Message)
	}
}
