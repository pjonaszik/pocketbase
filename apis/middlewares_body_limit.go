package apis

import (
	"io"
	"net/http"

	"github.com/pocketbase/pocketbase/core"
	"github.com/pocketbase/pocketbase/tools/hook"
	"github.com/pocketbase/pocketbase/tools/router"
)

var ErrRequestEntityTooLarge = router.NewApiError(http.StatusRequestEntityTooLarge, "Request entity too large", nil)

const DefaultMaxBodySize int64 = 32 << 20 // @todo consider replacing with router.DefaultMaxMemory

const (
	DefaultBodyLimitMiddlewareId       = "pbBodyLimit"
	DefaultBodyLimitMiddlewarePriority = DefaultRateLimitMiddlewarePriority + 10
)

// BodyLimit returns a middleware handler that changes the default request body size limit.
//
// If limitBytes <= 0, no limit is applied.
//
// Otherwise, if the request body size exceeds the configured limitBytes,
// it sends 413 error response.
func BodyLimit(limitBytes int64) *hook.Handler[*core.RequestEvent] {
	return &hook.Handler[*core.RequestEvent]{
		Id:       DefaultBodyLimitMiddlewareId,
		Priority: DefaultBodyLimitMiddlewarePriority,
		Func: func(e *core.RequestEvent) error {
			err := applyBodyLimit(e, limitBytes)
			if err != nil {
				return err
			}

			return e.Next()
		},
	}
}

func dynamicCollectionBodyLimit(collectionPathParam string) *hook.Handler[*core.RequestEvent] {
	if collectionPathParam == "" {
		collectionPathParam = "collection"
	}

	return &hook.Handler[*core.RequestEvent]{
		Id:       DefaultBodyLimitMiddlewareId,
		Priority: DefaultBodyLimitMiddlewarePriority,
		Func: func(e *core.RequestEvent) error {
			collection, err := e.App.FindCachedCollectionByNameOrId(e.Request.PathValue(collectionPathParam))
			if err != nil {
				return e.NotFoundError("Missing or invalid collection context.", err)
			}

			limitBytes := DefaultMaxBodySize
			if !collection.IsView() {
				for _, f := range collection.Fields {
					if calc, ok := f.(core.MaxBodySizeCalculator); ok {
						limitBytes += calc.CalculateMaxBodySize()
					}
				}
			}

			err = applyBodyLimit(e, limitBytes)
			if err != nil {
				return err
			}

			return e.Next()
		},
	}
}

func applyBodyLimit(e *core.RequestEvent, limitBytes int64) error {
	// no limit
	if limitBytes <= 0 {
		return nil
	}

	// optimistically check the submitted request content length
	if e.Request.ContentLength > limitBytes {
		return ErrRequestEntityTooLarge
	}

	// replace the request body
	//
	// note: we don't use sync.Pool since the size of the elements could vary too much
	// and it might not be efficient (see https://github.com/golang/go/issues/23199)
	e.Request.Body = &limitedReader{ReadCloser: e.Request.Body, limit: limitBytes}

	return nil
}

type limitedReader struct {
	io.ReadCloser
	limit     int64
	totalRead int64
	exceeded  bool
}

func (r *limitedReader) Read(b []byte) (int, error) {
	// the limit was already exceeded on a previous read: report the error
	// with n==0 so that readers which ignore an error returned together
	// with n>0 bytes (ex. the encoding/json/v2 jsontext decoder) still stop
	// and the rest of the (potentially oversized) body is not consumed
	if r.exceeded {
		return 0, ErrRequestEntityTooLarge
	}

	n, err := r.ReadCloser.Read(b)

	r.totalRead += int64(n)
	if r.totalRead > r.limit {
		// keep only the bytes up to the limit and defer the sentinel error
		// to the next Read (with n==0), so no reader can silently ignore it
		if over := int(r.totalRead - r.limit); over < n {
			n -= over
		} else {
			n = 0
		}
		r.totalRead = r.limit
		r.exceeded = true
		return n, err
	}

	return n, err
}

// explicit casts to ensure that the main struct methods will be invoked
// (extra precautions in case of nested interface wrapping erasure)
// ---

func (r *limitedReader) Reread() {
	rereader, ok := r.ReadCloser.(router.Rereader)
	if ok {
		rereader.Reread()
	}
}

func (r *limitedReader) Close() error {
	closer, ok := r.ReadCloser.(io.Closer)
	if ok {
		return closer.Close()
	}
	return nil
}
