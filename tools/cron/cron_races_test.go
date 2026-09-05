package cron

import (
	"sync/atomic"
	"testing"
	"time"
)

// A rapid Start/Stop cycle with a due job and a short interval must never
// deadlock. Regression test for the Stop() blocking send held under the
// write lock while the ticker goroutine needs the read lock (runDue).
func TestCronStartStopNoDeadlock(t *testing.T) {
	c := New()
	c.SetInterval(300 * time.Microsecond)
	for i := 0; i < 40; i++ {
		c.MustAdd("j", "* * * * *", func() {})
	}

	done := make(chan struct{})
	go func() {
		for i := 0; i < 2000; i++ {
			c.Start()
			// wait for the ticker to be established and let a tick buffer in
			// ticker.C, so Stop()'s blocking send races a ready ticker.C case
			for !c.HasStarted() {
				time.Sleep(50 * time.Microsecond)
			}
			time.Sleep(700 * time.Microsecond)
			c.Stop()
		}
		close(done)
	}()

	select {
	case <-done:
		// ok
	case <-time.After(20 * time.Second):
		t.Fatal("Start/Stop loop hung -> deadlock in Cron.Stop()")
	}
	c.Stop()
}

// Stop() during Start()'s startup-delay window must actually stop the cron:
// once Stop() returns, no job may keep firing.
func TestCronStopDuringStartupWindow(t *testing.T) {
	var runs int32

	for attempt := 0; attempt < 200; attempt++ {
		c := New()
		c.SetInterval(2 * time.Millisecond)
		c.MustAdd("j", "* * * * *", func() { atomic.AddInt32(&runs, 1) })

		c.Start()
		// stop somewhere inside the [0,interval) startup delay window
		time.Sleep(time.Duration(attempt%3) * time.Millisecond)
		c.Stop()

		if c.HasStarted() {
			t.Fatalf("attempt %d: HasStarted() is true after Stop() returned", attempt)
		}
	}

	// record the counter, wait well past several intervals, and ensure no
	// leaked ticker keeps firing jobs after every cron was stopped
	before := atomic.LoadInt32(&runs)
	time.Sleep(30 * time.Millisecond)
	after := atomic.LoadInt32(&runs)
	if after != before {
		t.Fatalf("jobs kept firing after Stop(): %d -> %d (leaked ticker)", before, after)
	}
}
