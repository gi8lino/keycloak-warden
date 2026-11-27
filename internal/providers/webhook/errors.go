package webhook

import (
	"cmp"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"syscall"
)

// transportErrorPrefix is shared by all webhook transport diagnostics.
const transportErrorPrefix = "webhook transport failed"

// webhookTransportError classifies transport failures without exposing raw error text.
// HTTP transport errors commonly contain a *url.Error with the destination URL;
// nested errors can also carry credentials, private hostnames, or request data.
// Only safe standard sentinel errors are retained in the returned error chain.
func webhookTransportError(err error) error {
	return cmp.Or(
		webhookContextError(err),
		webhookDNSError(err),
		webhookTLSError(err),
		webhookTimeoutError(err),
		webhookSocketError(err),
		webhookEOFError(err),
		webhookNetworkError(err),
		// Unknown errors may contain arbitrary request details; do not unwrap them.
		errors.New(transportErrorPrefix+": network error"),
	)
}

// webhookContextError preserves only safe cancellation and deadline sentinels.
func webhookContextError(err error) error {
	switch {
	case errors.Is(err, context.Canceled):
		return fmt.Errorf("%s: %w", transportErrorPrefix, context.Canceled)
	case errors.Is(err, context.DeadlineExceeded):
		return fmt.Errorf("%s: request timed out: %w", transportErrorPrefix, context.DeadlineExceeded)
	default:
		return nil
	}
}

// webhookDNSError keeps DNS failure categories but omits query names and messages.
func webhookDNSError(err error) error {
	dnsErr, ok := errors.AsType[*net.DNSError](err)
	if !ok {
		return nil
	}

	switch {
	case dnsErr.IsTimeout:
		return errors.New(transportErrorPrefix + ": DNS lookup timed out")
	case dnsErr.IsNotFound:
		return errors.New(transportErrorPrefix + ": DNS name not found")
	default:
		return errors.New(transportErrorPrefix + ": DNS lookup failed")
	}
}

// webhookTLSError identifies certificate and handshake failures without exposing
// certificate details, hostnames, or server-supplied protocol text.
func webhookTLSError(err error) error {
	if _, ok := errors.AsType[x509.UnknownAuthorityError](err); ok {
		return errors.New(transportErrorPrefix + ": TLS certificate authority not trusted")
	}
	if _, ok := errors.AsType[x509.HostnameError](err); ok {
		return errors.New(transportErrorPrefix + ": TLS certificate hostname mismatch")
	}
	if _, ok := errors.AsType[x509.CertificateInvalidError](err); ok {
		return errors.New(transportErrorPrefix + ": TLS certificate invalid")
	}
	if _, ok := errors.AsType[*tls.CertificateVerificationError](err); ok {
		return errors.New(transportErrorPrefix + ": TLS certificate verification failed")
	}
	if _, ok := errors.AsType[tls.RecordHeaderError](err); ok {
		return errors.New(transportErrorPrefix + ": TLS handshake failed")
	}
	if _, ok := errors.AsType[tls.AlertError](err); ok {
		return errors.New(transportErrorPrefix + ": TLS handshake failed")
	}
	if errors.Is(err, http.ErrSchemeMismatch) {
		return fmt.Errorf("%s: TLS handshake failed: %w", transportErrorPrefix, http.ErrSchemeMismatch)
	}

	return nil
}

// webhookTimeoutError keeps safe OS timeout identities and otherwise omits
// potentially sensitive text from custom net.Error implementations.
func webhookTimeoutError(err error) error {
	if errors.Is(err, syscall.ETIMEDOUT) {
		return fmt.Errorf("%s: %w", transportErrorPrefix, syscall.ETIMEDOUT)
	}

	if netErr, ok := errors.AsType[net.Error](err); ok && netErr.Timeout() {
		return errors.New(transportErrorPrefix + ": connection timed out")
	}

	return nil
}

// webhookSocketError retains only canonical syscall errors, never net.OpError
// or its address-bearing error chain.
func webhookSocketError(err error) error {
	switch {
	case errors.Is(err, syscall.ECONNREFUSED):
		return fmt.Errorf("%s: %w", transportErrorPrefix, syscall.ECONNREFUSED)
	case errors.Is(err, syscall.ENETUNREACH):
		return fmt.Errorf("%s: %w", transportErrorPrefix, syscall.ENETUNREACH)
	case errors.Is(err, syscall.EHOSTUNREACH):
		return fmt.Errorf("%s: %w", transportErrorPrefix, syscall.EHOSTUNREACH)
	case errors.Is(err, syscall.ENETDOWN):
		return fmt.Errorf("%s: %w", transportErrorPrefix, syscall.ENETDOWN)
	case errors.Is(err, syscall.ECONNRESET):
		return fmt.Errorf("%s: %w", transportErrorPrefix, syscall.ECONNRESET)
	case errors.Is(err, syscall.EPIPE):
		return fmt.Errorf("%s: %w", transportErrorPrefix, syscall.EPIPE)
	case errors.Is(err, net.ErrClosed):
		return fmt.Errorf("%s: %w", transportErrorPrefix, net.ErrClosed)
	default:
		return nil
	}
}

// webhookEOFError preserves safe EOF identities without the original error chain.
func webhookEOFError(err error) error {
	switch {
	case errors.Is(err, io.ErrUnexpectedEOF):
		return fmt.Errorf("%s: connection closed unexpectedly: %w", transportErrorPrefix, io.ErrUnexpectedEOF)
	case errors.Is(err, io.EOF):
		return fmt.Errorf("%s: connection closed unexpectedly: %w", transportErrorPrefix, io.EOF)
	default:
		return nil
	}
}

// webhookNetworkError recognizes opaque net.OpError failures without preserving
// potentially sensitive operation and address information.
func webhookNetworkError(err error) error {
	if _, ok := errors.AsType[*net.OpError](err); ok {
		return errors.New(transportErrorPrefix + ": connection error")
	}
	return nil
}
