// Command receiver prints Warden webhook requests to stdout for local testing.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	defaultListenAddress = ":8090"
	maxBodyBytes         = 64 << 10
	readHeaderTimeout    = 5 * time.Second
	shutdownTimeout      = 5 * time.Second
)

// receiver serializes readable HTTP request traces without interleaving them.
type receiver struct {
	mu    sync.Mutex
	count int
	out   io.Writer
}

// handler exposes a health check and a simple Warden webhook endpoint.
func handler(out io.Writer) http.Handler {
	service := &receiver{out: out}
	mux := http.NewServeMux()

	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})

	mux.HandleFunc("POST /webhook", service.webhook)
	return mux
}

// webhook prints all headers and the body, then acknowledges successful output.
func (service *receiver) webhook(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBodyBytes))
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			http.Error(w, "body too large", http.StatusRequestEntityTooLarge)
			return
		}
		http.Error(w, "could not read body", http.StatusBadRequest)
		return
	}

	var trace bytes.Buffer
	fmt.Fprintf(&trace, " %s %s\n", r.Method, r.URL.RequestURI())
	fmt.Fprintln(&trace, "Headers:")
	fmt.Fprintf(&trace, "  Host: %s\n", r.Host)

	keys := make([]string, 0, len(r.Header))
	for name := range r.Header {
		keys = append(keys, name)
	}
	slices.Sort(keys)
	for _, name := range keys {
		fmt.Fprintf(&trace, "  %s: %s\n", name, strings.Join(r.Header.Values(name), ", "))
	}

	fmt.Fprintf(&trace, "Body (%d bytes):\n", len(body))
	var pretty bytes.Buffer
	if err := json.Indent(&pretty, body, "  ", "  "); err == nil {
		trace.Write(pretty.Bytes())
	} else {
		trace.Write(body)
	}
	trace.WriteByte('\n')
	fmt.Fprintln(&trace, strings.Repeat("=", 36))

	service.mu.Lock()
	defer service.mu.Unlock()
	service.count++
	output := append([]byte(fmt.Sprintf("\n========== Webhook #%d", service.count)), trace.Bytes()...)
	if _, err := service.out.Write(output); err != nil {
		log.Printf("write webhook trace: %v", err)
		http.Error(w, "output unavailable", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// run serves requests until a shutdown signal is received.
func run() error {
	address := os.Getenv("LISTEN_ADDR")
	if address == "" {
		address = defaultListenAddress
	}

	server := &http.Server{
		Addr:              address,
		Handler:           handler(os.Stdout),
		ReadHeaderTimeout: readHeaderTimeout,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	stopped := make(chan error, 1)
	go func() {
		log.Printf("webhook receiver listening on %s", address)
		stopped <- server.ListenAndServe()
	}()

	select {
	case err := <-stopped:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()
		if err := server.Shutdown(shutdown); err != nil {
			return err
		}
		return nil
	}
}

// main starts the development receiver.
func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}
