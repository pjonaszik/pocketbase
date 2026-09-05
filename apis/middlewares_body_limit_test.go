package apis_test

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/pocketbase/pocketbase/apis"
	"github.com/pocketbase/pocketbase/core"
	"github.com/pocketbase/pocketbase/tests"
)

func TestBodyLimitMiddlewareStreaming(t *testing.T) {
	app, _ := tests.NewTestApp()
	defer app.Cleanup()

	pbRouter, err := apis.NewRouter(app)
	if err != nil {
		t.Fatal(err)
	}
	// handler that actually reads the body, so the streaming limitedReader
	// (not just the optimistic Content-Length check) is exercised
	pbRouter.POST("/read", func(e *core.RequestEvent) error {
		data := map[string]any{}
		if err := e.BindBody(&data); err != nil {
			return err
		}
		return e.String(200, "ok")
	}).Bind(apis.BodyLimit(20))

	mux, err := pbRouter.BuildMux()
	if err != nil {
		t.Fatal(err)
	}

	oversized := `{"a":"0123456789012345678901234567890123456789"}` // 47 bytes, over the 20 byte limit
	valid := `{"a":"ok"}`                                           // 10 bytes, under the limit

	scenarios := []struct {
		name           string
		body           string
		contentLength  int64
		expectedStatus int
	}{
		{"oversized with Content-Length", oversized, int64(len(oversized)), 413},
		{"oversized chunked", oversized, -1, 413},
		{"valid with Content-Length", valid, int64(len(valid)), 200},
		{"valid chunked", valid, -1, 200},
	}

	for _, s := range scenarios {
		t.Run(s.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, "/read", strings.NewReader(s.body))
			req.Header.Set("Content-Type", "application/json")
			req.ContentLength = s.contentLength

			mux.ServeHTTP(rec, req)

			if rec.Code != s.expectedStatus {
				t.Fatalf("expected status %d for a %d byte body (limit 20), got %d", s.expectedStatus, len(s.body), rec.Code)
			}
		})
	}
}

func TestBodyLimitMiddleware(t *testing.T) {
	app, _ := tests.NewTestApp()
	defer app.Cleanup()

	pbRouter, err := apis.NewRouter(app)
	if err != nil {
		t.Fatal(err)
	}
	pbRouter.POST("/a", func(e *core.RequestEvent) error {
		return e.String(200, "a")
	}) // default global BodyLimit check

	pbRouter.POST("/b", func(e *core.RequestEvent) error {
		return e.String(200, "b")
	}).Bind(apis.BodyLimit(20))

	mux, err := pbRouter.BuildMux()
	if err != nil {
		t.Fatal(err)
	}

	scenarios := []struct {
		url            string
		size           int64
		expectedStatus int
	}{
		{"/a", 21, 200},
		{"/a", apis.DefaultMaxBodySize + 1, 413},
		{"/b", 20, 200},
		{"/b", 21, 413},
	}

	for _, s := range scenarios {
		t.Run(fmt.Sprintf("%s_%d", s.url, s.size), func(t *testing.T) {
			rec := httptest.NewRecorder()
			req := httptest.NewRequest("POST", s.url, bytes.NewReader(make([]byte, s.size)))
			mux.ServeHTTP(rec, req)

			result := rec.Result()
			defer result.Body.Close()

			if result.StatusCode != s.expectedStatus {
				t.Fatalf("Expected response status %d, got %d", s.expectedStatus, result.StatusCode)
			}
		})
	}
}
