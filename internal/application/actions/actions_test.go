package actions

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/gi8lino/keycloak-warden/internal/application/decisions"
)

// blockingQueue waits for cancellation to test the worker's shutdown ordering.
type blockingQueue struct {
	// scriptedQueue supplies idle scheduling behavior.
	scriptedQueue
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
		defer func() { require.NoError(t, runner.Close()) }()
		select {
		case <-q.started:
		case <-time.After(3 * time.Second):
			require.FailNow(t, "worker did not start maintenance")
		}
		var closes sync.WaitGroup
		closeErrors := make(chan error, 2)
		for range 2 {
			closes.Go(func() { closeErrors <- runner.Close() })
		}
		closes.Wait()
		close(closeErrors)
		for err := range closeErrors {
			require.NoError(t, err)
		}
		require.NoError(t, runner.Wait())
		select {
		case <-runner.Done():
		default:
			require.FailNow(t, "Done did not close after Close returned")
		}
		select {
		case <-q.stopped:
		default:
			require.FailNow(t, "Close returned while worker still used the queue")
		}
	})
}

func TestRunnerWait(t *testing.T) {
	t.Parallel()

	t.Run("wait blocks until completion", func(t *testing.T) {
		t.Parallel()
		q := &blockingQueue{started: make(chan struct{}), stopped: make(chan struct{})}
		runner := Start(t.Context(), q, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
		defer func() { require.NoError(t, runner.Close()) }()
		<-q.started
		waitResult := make(chan error, 1)
		go func() { waitResult <- runner.Wait() }()
		select {
		case <-runner.Done():
			require.FailNow(t, "worker exited without cancellation")
		case err := <-waitResult:
			require.FailNow(t, "Wait returned before worker stopped", "returned error: %v", err)
		default:
		}
		require.NoError(t, runner.Close())
		require.NoError(t, <-waitResult)
	})

	t.Run("reports terminal errors to every waiter", func(t *testing.T) {
		t.Parallel()
		terminalErr := errors.New("terminal failure")
		finished := make(chan struct{})
		runner := &Runner{done: finished}
		runner.err = terminalErr
		close(finished)
		require.ErrorIs(t, runner.Wait(), terminalErr)
		require.ErrorIs(t, runner.Wait(), terminalErr)
	})
}

// scriptedQueue supplies a finite batch of jobs for drainReady.
type scriptedQueue struct {
	// changes wakes the test worker on demand.
	changes chan struct{}
	// deadlines supplies successive wake times in worker order.
	deadlines []time.Time
	// cycles counts reads of the upcoming deadline.
	cycles atomic.Int32
	// jobs contains the queued jobs supplied by the test.
	jobs []*Job
	// finished records jobs acknowledged by the worker.
	finished []Job
}

// Changes returns the test change notification channel.
func (q *scriptedQueue) Changes() <-chan struct{} { return q.changes }

// NextDeadline counts completed cycles and supplies the test deadline.
func (q *scriptedQueue) NextDeadline(context.Context) (time.Time, error) {
	cycle := int(q.cycles.Add(1))
	if cycle > len(q.deadlines) {
		return time.Time{}, nil
	}
	return q.deadlines[cycle-1], nil
}

// Prune accepts periodic observation cleanup.
func (q *scriptedQueue) Prune(context.Context, time.Time) error { return nil }

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
		require.NoError(t, drainReady(t.Context(), q, map[string]Provider{"target": provider}, logger, time.Now().Add(time.Second)))

		assert.Equal(t, 2, provider.applied)
		assert.Len(t, q.finished, 2)
	})

	t.Run("respects expired deadline", func(t *testing.T) {
		t.Parallel()

		q := &scriptedQueue{jobs: []*Job{{Decision: decisions.Decision{ID: "one"}, Destination: "target"}}}
		provider := &acceptProvider{}
		require.NoError(t, drainReady(t.Context(), q, map[string]Provider{"target": provider}, slog.Default(), time.Now().Add(-time.Second)))

		assert.Zero(t, provider.applied)
		assert.Empty(t, q.finished)
	})
}

func TestWorkerWakeups(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		q := &scriptedQueue{changes: make(chan struct{}, 1), deadlines: []time.Time{{}, time.Now().Add(11 * time.Minute)}}
		r := Start(t.Context(), q, nil, slog.Default())
		defer func() { require.NoError(t, r.Close()) }()
		synctest.Wait()
		require.Equal(t, 1, int(q.cycles.Load()))
		time.Sleep(10 * time.Minute)
		synctest.Wait()
		require.Equal(t, 1, int(q.cycles.Load()))

		q.changes <- struct{}{}
		synctest.Wait()
		require.Equal(t, 2, int(q.cycles.Load()))
		time.Sleep(time.Minute)
		synctest.Wait()
		require.Equal(t, 3, int(q.cycles.Load()))
	})
}
