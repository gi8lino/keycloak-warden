package actions

import (
	"context"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/gi8lino/keycloak-warden/internal/application/decisions"
)

// blockingQueue waits for cancellation to test the worker's shutdown ordering.
type blockingQueue struct {
	// started signals that the test worker entered the operation.
	started chan struct{}
	// stopped signals that the test worker observed cancellation.
	stopped chan struct{}
}

// Maintain blocks until cancellation so Close must wait for it to return.
func (q *blockingQueue) Maintain(ctx context.Context, _ time.Time) error {
	close(q.started)
	<-ctx.Done()
	close(q.stopped)
	return ctx.Err()
}

// Next is not reached while Maintain blocks.
func (q *blockingQueue) Next(context.Context, time.Time) (*Job, error) { return nil, nil }

// Finish is not reached while Maintain blocks.
func (q *blockingQueue) Finish(context.Context, Job, bool, time.Time) error { return nil }

func TestStart(t *testing.T) {
	t.Parallel()

	t.Run("starts worker and can close concurrently", func(t *testing.T) {
		t.Parallel()

		q := &blockingQueue{started: make(chan struct{}), stopped: make(chan struct{})}
		runner := Start(t.Context(), q, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
		defer runner.Close()
		select {
		case <-q.started:
		case <-time.After(3 * time.Second):
			require.FailNow(t, "worker did not start maintenance")
		}
		var closes sync.WaitGroup
		for range 2 {
			closes.Go(runner.Close)
		}
		closes.Wait()
		select {
		case <-q.stopped:
		default:
			require.FailNow(t, "Close returned while worker still used the queue")
		}
	})
}

// scriptedQueue supplies a finite batch of jobs for drainReady.
type scriptedQueue struct {
	// jobs contains the queued jobs supplied by the test.
	jobs []*Job
	// finished records jobs acknowledged by the worker.
	finished []Job
}

// Maintain is unused by drainReady.
func (q *scriptedQueue) Maintain(context.Context, time.Time) error { return nil }

// Next returns one available job or nil when drained.
func (q *scriptedQueue) Next(context.Context, time.Time) (*Job, error) {
	if len(q.jobs) == 0 {
		return nil, nil
	}
	job := q.jobs[0]
	q.jobs = q.jobs[1:]
	return job, nil
}

// Finish records successfully dispatched work.
func (q *scriptedQueue) Finish(_ context.Context, job Job, success bool, _ time.Time) error {
	if success {
		q.finished = append(q.finished, job)
	}
	return nil
}

// acceptProvider records successful application of a decision.
type acceptProvider struct {
	// applied records decisions delivered to the test provider.
	applied int
}

// Apply records delivery and accepts the decision.
func (p *acceptProvider) Apply(context.Context, decisions.Decision) error {
	p.applied++
	return nil
}

func TestDrainReady(t *testing.T) {
	t.Parallel()

	t.Run("drains all ready jobs before deadline", func(t *testing.T) {
		t.Parallel()

		q := &scriptedQueue{jobs: []*Job{
			{Decision: decisions.Decision{ID: "one"}, Destination: "target"},
			{Decision: decisions.Decision{ID: "two"}, Destination: "target"},
		}}
		provider := &acceptProvider{}
		logger := slog.New(slog.NewTextHandler(io.Discard, nil))
		drainReady(t.Context(), q, map[string]Provider{"target": provider}, logger, time.Now().Add(time.Second))

		assert.Equal(t, 2, provider.applied)
		assert.Len(t, q.finished, 2)
	})

	t.Run("respects expired deadline", func(t *testing.T) {
		t.Parallel()

		q := &scriptedQueue{jobs: []*Job{{Decision: decisions.Decision{ID: "one"}, Destination: "target"}}}
		provider := &acceptProvider{}
		drainReady(t.Context(), q, map[string]Provider{"target": provider}, slog.Default(), time.Now().Add(-time.Second))

		assert.Zero(t, provider.applied)
		assert.Empty(t, q.finished)
	})
}
