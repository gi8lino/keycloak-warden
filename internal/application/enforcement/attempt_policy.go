package enforcement

import (
	"errors"

	"github.com/gi8lino/keycloak-warden/pkg/model"
)

// AttemptLimit is the application-owned policy for a delivery's completed attempts.
type AttemptLimit int

// Validate rejects budgets that cannot accommodate an initial send.
func (p AttemptLimit) Validate() error {
	if p < 1 {
		return errors.New("max-attempts must be at least 1")
	}
	return nil
}

// AfterFailure determines the resulting status from the transaction's attempt count.
func (p AttemptLimit) AfterFailure(completed int64) model.DeliveryStatus {
	if completed >= int64(p) {
		return model.DeliveryExhausted
	}
	return model.DeliveryRetrying
}
