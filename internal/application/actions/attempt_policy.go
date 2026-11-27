package actions

import "github.com/gi8lino/keycloak-warden/pkg/model"

// StatusAfterFailure chooses whether a failed delivery may be retried based on
// its completed attempt count and the configured maximum number of attempts.
func StatusAfterFailure(completed int64, maxAttempts int) model.DeliveryStatus {
	if completed >= int64(maxAttempts) {
		return model.DeliveryExhausted
	}
	return model.DeliveryRetrying
}
