// Package signing implements timestamped HMAC over exact HTTP request bytes.
package signing

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"strings"
	"time"
)

const (
	// signaturePrefix identifies the supported HMAC signing protocol version.
	signaturePrefix = "v1="
	// maxClockSkew tolerates timestamps within five minutes of receipt.
	maxClockSkew = 5 * time.Minute
)

// Signature returns the v1 HMAC header for a timestamp and raw body.
func Signature(secret, timestamp string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(timestamp + "."))
	mac.Write(body)
	return signaturePrefix + hex.EncodeToString(mac.Sum(nil))
}

// Valid checks timestamp freshness and compares the provided digest in constant time.
func Valid(secret, timestamp, signature string, body []byte, now time.Time) bool {
	if !fresh(timestamp, now) {
		return false
	}
	return strings.HasPrefix(signature, signaturePrefix) &&
		hmac.Equal([]byte(signature), []byte(Signature(secret, timestamp, body)))
}

// fresh accepts canonical decimal Unix seconds within five minutes of receipt.
func fresh(timestamp string, now time.Time) bool {
	seconds, err := strconv.ParseInt(timestamp, 10, 64)
	if err != nil || strconv.FormatInt(seconds, 10) != timestamp {
		return false
	}
	skewSeconds := int64(maxClockSkew / time.Second)
	return seconds >= now.Unix()-skewSeconds && seconds <= now.Unix()+skewSeconds
}
