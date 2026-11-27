package overview

import (
	"context"
	"fmt"

	"github.com/gi8lino/keycloak-warden/pkg/model"
)

// NotificationStore supplies bounded, read-only incident delivery history.
type NotificationStore interface {
	// ListNotifications reads at most limit occurrence delivery records.
	ListNotifications(context.Context, int64, int) ([]model.NotificationDelivery, error)
	// ListNotificationAttempts reads at most limit completed sends for a delivery.
	ListNotificationAttempts(context.Context, int64, int64, int) ([]model.NotificationAttempt, error)
}

// NotificationService validates and paginates incident delivery queries.
type NotificationService struct {
	// store supplies the persisted notification projections.
	store NotificationStore
}

// NewNotificationService creates a read-only notification overview.
func NewNotificationService(store NotificationStore) *NotificationService {
	return &NotificationService{store: store}
}

// Deliveries returns one page of retained notification deliveries.
func (s *NotificationService) Deliveries(ctx context.Context, before int64) (model.NotificationPage, error) {
	if before < 0 {
		return model.NotificationPage{}, fmt.Errorf("%w: invalid notification cursor", ErrInvalid)
	}
	items, err := s.store.ListNotifications(ctx, before, PageSize+1)
	if err != nil {
		return model.NotificationPage{}, err
	}
	result := model.NotificationPage{Items: items}
	if len(items) > PageSize {
		result.Items = items[:PageSize]
		result.NextBeforeID = result.Items[PageSize-1].ID
	}
	return result, nil
}

// Attempts returns one page of recorded sends for a notification delivery.
func (s *NotificationService) Attempts(ctx context.Context, id, before int64) (model.NotificationAttemptPage, error) {
	if id < 1 || before < 0 {
		return model.NotificationAttemptPage{}, fmt.Errorf("%w: invalid notification attempt selector", ErrInvalid)
	}
	items, err := s.store.ListNotificationAttempts(ctx, id, before, PageSize+1)
	if err != nil {
		return model.NotificationAttemptPage{}, err
	}
	result := model.NotificationAttemptPage{Items: items}
	if len(items) > PageSize {
		result.Items = items[:PageSize]
		result.NextBeforeNumber = int64(result.Items[PageSize-1].Number)
	}
	return result, nil
}
