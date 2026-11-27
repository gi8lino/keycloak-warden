package notifications

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/gi8lino/keycloak-warden/internal/retry"
	"github.com/gi8lino/keycloak-warden/pkg/model"
)

// senderFunc adapts a test function to an incident sender.
type senderFunc func(context.Context, model.Incident) error

// Deliver calls the configured test sender.
func (f senderFunc) Deliver(ctx context.Context, incident model.Incident) error {
	return f(ctx, incident)
}

// testQueue captures delivery completions from a single worker.
type testQueue struct {
	// jobs supplies ready occurrences.
	jobs chan Job
	// changes wakes the worker on new work.
	changes chan struct{}
	// completions captures the resulting queue state.
	completions chan Completion
}

// NotificationChanges returns the queue's wakeup channel.
func (q *testQueue) NotificationChanges() <-chan struct{} { return q.changes }

// NextNotificationDeadline reports an idle queue; new jobs wake the worker explicitly.
func (q *testQueue) NextNotificationDeadline(context.Context) (time.Time, error) {
	return time.Time{}, nil
}

// NextNotification returns a ready job if one is available.
func (q *testQueue) NextNotification(context.Context, time.Time) (*Job, error) {
	select {
	case job := <-q.jobs:
		return &job, nil
	default:
		return nil, nil
	}
}

// FinishNotification captures an attempt's completion.
func (q *testQueue) FinishNotification(_ context.Context, _ Job, completion Completion) error {
	q.completions <- completion
	return nil
}

func TestComplete(t *testing.T) {
	t.Parallel()

	t.Run("schedules a retry after a failed send", func(t *testing.T) {
		t.Parallel()

		now := time.Now()
		result := Complete(Job{}, errors.New("receiver unavailable"), 3, now, time.Second)
		assert.Equal(t, Pending, result.State)
		assert.Equal(t, 1, result.Attempts)
		assert.Equal(t, now.Add(time.Second), result.NextAt)
		assert.True(t, result.CompletedAt.IsZero())
	})

	t.Run("exhausts the last attempt", func(t *testing.T) {
		t.Parallel()

		now := time.Now()
		result := Complete(Job{Attempts: 2}, errors.New("receiver unavailable"), 3, now, time.Second)
		assert.Equal(t, Exhausted, result.State)
		assert.Equal(t, 3, result.Attempts)
		assert.Equal(t, now, result.CompletedAt)
		assert.Zero(t, result.Delay)
	})

	t.Run("acknowledges a successful send", func(t *testing.T) {
		t.Parallel()

		now := time.Now()
		result := Complete(Job{Attempts: 1}, nil, 3, now, time.Second)
		assert.Equal(t, Delivered, result.State)
		assert.Equal(t, 2, result.Attempts)
		assert.Equal(t, now, result.CompletedAt)
	})

	t.Run("manual retry preserves lifetime attempts", func(t *testing.T) {
		t.Parallel()

		now := time.Now()
		job := Job{
			Attempts:      5,
			RetryBaseline: 5,
		}
		result := Complete(job, errors.New("receiver unavailable"), 2, now, time.Second)

		assert.Equal(t, Pending, result.State)
		assert.Equal(t, 6, result.Attempts)
		assert.True(t, result.Attempted)
		assert.Equal(t, "receiver unavailable", result.Error)
	})

	t.Run("reduced budget does not invent an attempt", func(t *testing.T) {
		t.Parallel()

		now := time.Now()
		result := Complete(Job{Attempts: 3}, errors.New("budget exhausted"), 2, now, time.Second)

		assert.Equal(t, Exhausted, result.State)
		assert.Equal(t, 3, result.Attempts)
		assert.False(t, result.Attempted)
		assert.Equal(t, now, result.CompletedAt)
	})

}

func TestRunner(t *testing.T) {
	t.Parallel()

	t.Run("wakes for selected work and records retry outcome", func(t *testing.T) {
		t.Parallel()

		q := &testQueue{
			jobs:        make(chan Job, 1),
			changes:     make(chan struct{}, 1),
			completions: make(chan Completion, 1),
		}
		targets := map[string]Target{
			"slack-ops": {
				Provider: senderFunc(func(_ context.Context, item model.Incident) error {
					assert.Equal(t, int64(7), item.ID)
					return errors.New("receiver unavailable")
				}),
				MaxAttempts: 3,
			},
		}
		logger := slog.New(slog.NewTextHandler(io.Discard, nil))
		runner := Start(t.Context(), q, targets, retry.DefaultRetryPolicy(), logger)
		defer runner.Close()

		q.jobs <- Job{
			ID:          1,
			Incident:    model.Incident{ID: 7},
			Destination: "slack-ops",
		}
		q.changes <- struct{}{}
		var result Completion
		select {
		case result = <-q.completions:
		case <-time.After(2 * time.Second):
			require.FailNow(t, "notification worker did not process job")
		}
		assert.Equal(t, Pending, result.State)
		assert.Equal(t, 10*time.Second, result.Delay)
		assert.Equal(t, 1, result.Attempts)
	})

	t.Run("cancels in-flight delivery without consuming attempt", func(t *testing.T) {
		t.Parallel()

		q := &testQueue{
			jobs:        make(chan Job, 1),
			changes:     make(chan struct{}, 1),
			completions: make(chan Completion, 1),
		}
		started := make(chan struct{})
		targets := map[string]Target{
			"audit": {
				Provider: senderFunc(func(ctx context.Context, _ model.Incident) error {
					close(started)
					<-ctx.Done()
					return ctx.Err()
				}),
				MaxAttempts: 3,
			},
		}
		q.jobs <- Job{Destination: "audit"}
		logger := slog.New(slog.NewTextHandler(io.Discard, nil))
		runner := Start(t.Context(), q, targets, retry.DefaultRetryPolicy(), logger)
		defer runner.Close()
		select {
		case <-started:
		case <-time.After(2 * time.Second):
			require.FailNow(t, "notification worker did not start delivery")
		}
		runner.Close()
		assert.Empty(t, q.completions)
		assert.Equal(t, model.WorkerStopped, runner.Snapshot().State)
	})
}
