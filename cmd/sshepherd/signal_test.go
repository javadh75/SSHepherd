package main

import (
	"context"
	"os"
	"syscall"
	"testing"
	"time"
)

// TestWatchSignalsSecondSignalExits: the first signal only cancels; a second
// one exits with 128+signo. In a container sshepherd can be PID 1, where the
// kernel ignores default signal actions, so the forced exit must be explicit.
func TestWatchSignalsSecondSignalExits(t *testing.T) {
	for _, tt := range []struct {
		name   string
		second os.Signal
		want   int
	}{
		{"SIGINT", os.Interrupt, 130},
		{"SIGTERM", syscall.SIGTERM, 143},
	} {
		t.Run(tt.name, func(t *testing.T) {
			sigs := make(chan os.Signal, 2)
			exited := make(chan int, 1)
			ctx, stop := watchSignals(context.Background(), sigs, func(code int) { exited <- code })
			defer stop()

			sigs <- syscall.SIGTERM
			select {
			case <-ctx.Done():
			case <-time.After(2 * time.Second):
				t.Fatal("first signal did not cancel the context")
			}
			select {
			case code := <-exited:
				t.Fatalf("first signal exited the process (code %d); it must only cancel", code)
			case <-time.After(50 * time.Millisecond):
			}

			sigs <- tt.second
			select {
			case code := <-exited:
				if code != tt.want {
					t.Errorf("exit code = %d, want %d", code, tt.want)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("second signal did not exit")
			}
		})
	}
}

// TestWatchSignalsStopEndsWatcher: stop releases the watcher goroutine (goleak
// in TestMain fails the package otherwise) and cancels the context.
func TestWatchSignalsStopEndsWatcher(t *testing.T) {
	sigs := make(chan os.Signal, 2)
	ctx, stop := watchSignals(context.Background(), sigs, func(int) { t.Error("exit called without a signal") })
	stop()
	if ctx.Err() == nil {
		t.Error("stop did not cancel the context")
	}
}
