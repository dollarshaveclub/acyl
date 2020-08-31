package locker

import (
	"context"
	"math/rand"
	"os"
	"testing"
	"time"
)

const (
	defaultPostgresLockWaitTime = 5 * time.Second
)

func TestPostgresPreemptiveLocker(t *testing.T) {
	if os.Getenv("POSTGRES_ALREADY_RUNNING") == "" {
		t.Skip()
	}

	ttc := &testTableCoordinator{}
	err := ttc.setup()
	if err != nil {
		t.Fatalf("unable to create tables: %v", err)
	}
	defer func() {
		if err := ttc.destroy(); err != nil {
			t.Logf("error destroying tables: %v", err)
		}
	}()
	runPreemptiveLockerTests(t, func(t *testing.T) LockProvider {
		pl, err := NewPostgresLockProvider(testpostgresURI, "postgres_locker", false)
		if err != nil {
			t.Fatalf("unable to create postgres lock provider: %v", err)
		}
		return pl
	})
}

func TestFakePreemptiveLocker(t *testing.T) {
	runPreemptiveLockerTests(t, func(t *testing.T) LockProvider {
		return NewFakeLockProvider()
	})
}

func runPreemptiveLockerTests(t *testing.T, plfunc pLFactoryFunc) {
	if plfunc == nil {
		t.Fatalf("plfunc cannot be nil")
	}
	tests := []struct {
		name  string
		tfunc func(*testing.T, LockProvider)
	}{
		{
			name:  "release before locking should return an error",
			tfunc: testPreemptiveLockerReleaseBeforeLock,
		},
		{
			name:  "locking more than once should return an error",
			tfunc: testPreemptiveLockerLocksOnlyOnce,
		},
		{
			name:  "lock and release",
			tfunc: testPreemptiveLockerLockAndRelease,
		},
		{
			name:  "configurable lock delay",
			tfunc: testPreemptiveLockerLockDelay,
		},
		{
			name:  "new preemptive locker should respect canceled context",
			tfunc: testNewPreemptiveLockerCancelledContext,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.tfunc == nil {
				t.Skip("test func is nil")
			}
			tt.tfunc(t, plfunc(t))
		})
	}
}

func testPreemptiveLockerReleaseBeforeLock(t *testing.T, lp LockProvider) {
	plf, err := NewPreemptiveLockerFactory(lp)
	if err != nil {
		t.Fatalf("error creating new preemptive locker factory: %v", err)
	}
	repo := "foo/bar"
	pr := uint(rand.Uint32())
	pl := plf(repo, pr, "update")

	// Attempting to Release before calling Lock should fail
	err = pl.Release(context.Background())
	if err == nil {
		t.Fatalf("expected error when Releasing before Locking")
	}
}

func testPreemptiveLockerLocksOnlyOnce(t *testing.T, lp LockProvider) {
	plf, err := NewPreemptiveLockerFactory(
		lp,
		WithLockDelay(time.Second),
		WithLockWait(defaultPostgresLockWaitTime),
	)
	if err != nil {
		t.Fatalf("error creating new preemptive locker factory: %v", err)
	}
	repo := "foo/bar"
	pr := uint(rand.Uint32())
	pl := plf(repo, pr, "update")
	_, err = pl.Lock(context.Background())
	if err != nil {
		t.Fatalf("unexpected error when locking: %v", err)
	}
	defer pl.Release(context.Background())

	// Attempting to lock again from the same preemptive locker should fail
	_, err = pl.Lock(context.Background())
	if err == nil {
		t.Fatalf("expected error when attempting to lock already held lock")
	}
}

func testPreemptiveLockerLockAndRelease(t *testing.T, lp LockProvider) {
	plf, err := NewPreemptiveLockerFactory(
		lp,
		WithLockDelay(time.Second),
		WithLockWait(defaultPostgresLockWaitTime),
	)
	if err != nil {
		t.Fatalf("error creating new preemptive locker factory: %v", err)
	}
	// Should be able to lock
	repo := "foo/bar"
	pr := uint(rand.Uint32())
	pl := plf(repo, pr, "update")
	ctx, cancel := context.WithTimeout(context.Background(), defaultPostgresLockWaitTime)
	defer cancel()
	preempt, err := pl.Lock(ctx)
	if err != nil {
		t.Fatalf("unexpected error when locking: %v", err)
	}

	// Lock should not be preempted
	select {
	case <-preempt:
		t.Fatalf("should not have been preempted")
	default:
		break
	}

	pl2 := plf(repo, pr, "update")
	// New PreemptiveLocker should fail to lock (due to LockWait timeout)
	_, err = pl2.Lock(context.Background())
	if err == nil {
		t.Fatalf("should have failed to acquire second lock on same key")
	}
	defer pl2.Release(context.Background())

	select {
	case <-preempt:
		// first lock was preempted, release the lock
		err := pl.Release(context.Background())
		if err != nil {
			t.Fatalf("error releasing the lock: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("original lock was not preempted")
	}

	// New PreemptiveLocker should be able to acquire lock now
	pl3 := plf(repo, pr, "update")
	_, err = pl3.Lock(context.Background())
	if err != nil {
		t.Fatalf("should have been able to lock the key: %v", err)
	}

	defer pl3.Release(context.Background())
}
func testPreemptiveLockerLockDelay(t *testing.T, lp LockProvider) {
	lockDelay := 2 * time.Second
	plf, err := NewPreemptiveLockerFactory(
		lp,
		WithLockDelay(lockDelay),
		WithLockWait(defaultPostgresLockWaitTime),
	)
	if err != nil {
		t.Fatalf("error creating new preemptive locker factory: %v", err)
	}
	repo := "foo/bar"
	pr := uint(rand.Uint32())
	pl := plf(repo, pr, "update")
	start := time.Now()
	_, err = pl.Lock(context.Background())
	if err != nil {
		t.Fatalf("unexpected error locking: %v", err)
	}

	defer pl.lock.Unlock(context.Background())

	d := time.Since(start)
	if d < lockDelay {
		t.Fatalf("lock delay value was not respected: %v", err)
	}
}

func testNewPreemptiveLockerCancelledContext(t *testing.T, lp LockProvider) {
	plf, err := NewPreemptiveLockerFactory(
		lp,
		WithLockDelay(time.Second),
		WithLockWait(defaultPostgresLockWaitTime),
	)
	if err != nil {
		t.Fatalf("error creating new preemptive locker factory: %v", err)
	}
	repo := "foo/bar"
	pr := uint(rand.Uint32())
	pl := plf(repo, pr, "update")
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	cancel()
	_, err = pl.Lock(ctx)
	if err == nil {
		t.Fatalf("expected error when locking with a canceled context")
	}
	defer pl.Release(context.Background())
}
