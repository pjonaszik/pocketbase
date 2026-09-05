package jsvm

import (
	"fmt"
	"net"
	"testing"

	"github.com/dop251/goja"
)

// $http.send must throw when the response body cannot be fully read (a
// mid-body network error), per the docs contract "throws on timeout or
// network connectivity error", instead of returning a truncated body as
// a successful HTTP 200.
func TestHTTPSendBodyReadError(t *testing.T) {
	// server that promises 1000 bytes but writes 5 and closes -> io.ErrUnexpectedEOF on read
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, 4096)
		_, _ = conn.Read(buf) // consume the request
		fmt.Fprint(conn, "HTTP/1.1 200 OK\r\nContent-Length: 1000\r\nConnection: close\r\n\r\nshort")
	}()

	vm := goja.New()
	BindCore(vm)
	BindHTTP(vm)
	vm.Set("testURL", "http://"+ln.Addr().String())

	v, err := vm.RunString(`
		(function () {
			try {
				const r = $http.send({ url: testURL });
				return JSON.stringify({ threw: false, statusCode: r.statusCode, body: r.raw });
			} catch (e) {
				return JSON.stringify({ threw: true });
			}
		})()
	`)
	if err != nil {
		t.Fatal(err)
	}

	got := v.Export().(string)
	t.Logf("observed: %s", got)
	if got != `{"threw":true}` {
		t.Fatalf("expected $http.send to throw on a mid-body read error, got %s", got)
	}
}
