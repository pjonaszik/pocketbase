package core_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pocketbase/pocketbase/core"
	"github.com/pocketbase/pocketbase/tests"
)

// When the restore's second dir-swap (extracted -> pb_data) fails after the
// first (pb_data -> temp) succeeded, RestoreBackup must revert so pb_data is
// left intact, per its doc contract "the dir changes are reverted".
func TestRestoreBackupRevertsWhenSecondMoveFails(t *testing.T) {
	if os.Getenv("CI") == "" {
		// this test manipulates unix dir permissions; skip on non-unix is implicit
	}

	app, _ := tests.NewTestApp()
	defer app.Cleanup()

	// guard: if the restore ever reaches Restart() (i.e. the injection missed
	// its window and the second move unexpectedly succeeded), block the execve
	// so we don't re-exec the test binary; the assertions below will then flag it.
	app.OnTerminate().BindFunc(func(e *core.TerminateEvent) error {
		return nil // swallow: do not call e.Next() -> no execve
	})

	if err := app.CreateBackup(context.Background(), "test.zip"); err != nil {
		t.Fatal(err)
	}

	// widen the first-move window so the watcher reliably chmods the extracted
	// dir before the second move starts
	for i := 0; i < 2000; i++ {
		_ = os.WriteFile(filepath.Join(app.DataDir(), "pad_"+strings.Repeat("x", 3)+itoa(i)+".txt"), []byte("x"), 0644)
	}

	tempDir := filepath.Join(app.DataDir(), core.LocalTempDirName)

	var stop atomic.Bool
	var injected atomic.Bool
	go func() {
		for !stop.Load() {
			// wait until the FIRST move has started (old_pb_data_* exists), which
			// guarantees the extraction is complete and the SECOND move has not
			// happened yet, then make the extracted dir read-only so the second
			// move's rename fails without disturbing the extraction or the first move
			if started, _ := filepath.Glob(filepath.Join(tempDir, "old_pb_data_*")); len(started) > 0 {
				matches, _ := filepath.Glob(filepath.Join(tempDir, "pb_restore_*"))
				for _, m := range matches {
					if os.Chmod(m, 0o500) == nil {
						injected.Store(true)
					}
				}
			}
		}
	}()

	restoreErr := app.RestoreBackup(context.Background(), "test.zip")
	stop.Store(true)
	time.Sleep(20 * time.Millisecond)

	// re-open perms so cleanup can remove the temp dirs
	if matches, _ := filepath.Glob(filepath.Join(tempDir, "pb_restore_*")); matches != nil {
		for _, m := range matches {
			_ = os.Chmod(m, 0o700)
		}
	}

	if !injected.Load() {
		t.Skip("could not inject the second-move failure in time; window missed")
	}

	if restoreErr == nil || !strings.Contains(restoreErr.Error(), "extracted archive content") {
		t.Fatalf("expected the second move to fail, got restoreErr=%v", restoreErr)
	}

	// the contract: after a failed restore, pb_data must be intact
	if _, err := os.Stat(filepath.Join(app.DataDir(), "data.db")); err != nil {
		t.Fatalf("pb_data was not reverted: data.db missing after failed restore (%v)", err)
	}
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	return string(b)
}
