package webhook

import (
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
	if result := webhookContextError(err); result != nil {
		return result
	}
	if result := webhookDNSError(err); result != nil {
		return result
	}
	if result := webhookTLSError(err); result != nil {
		return result
	}
	if result := webhookTimeoutError(err); result != nil {
		return result
	}
	if result := webhookSocketError(err); result != nil {
		return result
	}
	if result := webhookEOFError(err); result != nil {
		return result
	}
	if result := webhookNetworkError(err); result != nil {
		return result
	}

	// Unknown errors may contain arbitrary request details; do not unwrap them.
	return errors.New(transportErrorPrefix + ": network error")
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
	var dnsErr *net.DNSError
	if !errors.As(err, &dnsErr) {
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
	var unknownAuthority x509.UnknownAuthorityError
	if errors.As(err, &unknownAuthority) {
		return errors.New(transportErrorPrefix + ": TLS certificate authority not trusted")
	}

	var hostnameError x509.HostnameError
	if errors.As(err, &hostnameError) {
		return errors.New(transportErrorPrefix + ": TLS certificate hostname mismatch")
	}

	var invalidCertificate x509.CertificateInvalidError
	if errors.As(err, &invalidCertificate) {
		return errors.New(transportErrorPrefix + ": TLS certificate invalid")
	}

	var certificateVerification *tls.CertificateVerificationError
	if errors.As(err, &certificateVerification) {
		return errors.New(transportErrorPrefix + ": TLS certificate verification failed")
	}

	var recordHeader tls.RecordHeaderError
	var tlsAlert tls.AlertError
	if errors.As(err, &recordHeader) || errors.As(err, &tlsAlert) {
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

	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
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
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		return errors.New(transportErrorPrefix + ": connection error")
	}
	return nil
}
