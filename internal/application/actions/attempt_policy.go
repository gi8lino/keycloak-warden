package actions

import "github.com/gi8lino/keycloak-warden/pkg/deliverystate"

// StatusAfterFailure chooses whether a failed delivery may be retried based on
// its completed attempt count and the configured maximum number of attempts.
func StatusAfterFailure(completed int64, maxAttempts int) deliverystate.Status {
	if completed >= int64(maxAttempts) {
		return deliverystate.StatusExhausted
	}
	return deliverystate.StatusRetrying
}
