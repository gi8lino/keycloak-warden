package bootstrap

import (
	"fmt"
	"maps"
	"slices"
	"time"

	"github.com/gi8lino/keycloak-warden/internal/application/notifications"
	"github.com/gi8lino/keycloak-warden/internal/config"
	"github.com/gi8lino/keycloak-warden/internal/retry"
	"github.com/gi8lino/keycloak-warden/pkg/model"
)

// Notifications resolves named incident destinations separately from enforcement providers.
func Notifications(cfg config.Notifications) (map[string]notifications.Target, error) {
	if err := cfg.Validate(nil); err != nil {
		return nil, err
	}

	client, registry := providerDependencies()
	targets := make(map[string]notifications.Target)
	limit := effectiveMaxAttempts(cfg.MaxAttempts, retry.DefaultMaxAttempts)

	for _, name := range slices.Sorted(maps.Keys(cfg.Webhook)) {
		settings := cfg.Webhook[name]

		provider, err := buildWebhook(settings, client, registry, incidentSamples()...)
		if err != nil {
			return nil, fmt.Errorf("notification %q: %w", name, err)
		}

		targets[name] = notifications.Target{
			Provider:    provider,
			Identity:    webhookIdentity(provider),
			MaxAttempts: effectiveMaxAttempts(settings.MaxAttempts, limit),
		}
	}
	return targets, nil
}

// incidentSamples covers user and administrative events with optional ban fields.
func incidentSamples() []model.Incident {
	user := model.Incident{
		ID:        1,
		Rule:      "startup-check",
		EventKind: "user",
		EventType: "LOGIN_ERROR",
		IP:        "203.0.113.1",
		RealmID:   "example",
		Count:     5,
		Threshold: 5,
		At:        time.Unix(0, 0).UTC(),
		GroupBy:   "ip",
		GroupKey:  "203.0.113.1",
	}
	admin := model.Incident{
		ID:            2,
		Rule:          "startup-check",
		EventKind:     "admin",
		OperationType: "CREATE",
		ResourceType:  "USER",
		RealmID:       "example",
		Count:         1,
		Threshold:     1,
		At:            user.At,
		GroupBy:       "realm",
		GroupKey:      "example",
	}
	banned := user
	expires := user.At.Add(time.Minute)
	banned.BanUntil = &expires
	banned.EffectiveBanUntil = &expires
	banned.DecisionID = "startup-check"
	banned.DecisionRevision = 1
	observed := banned
	observed.ObserveOnly = true
	observed.DecisionID = ""
	observed.DecisionRevision = 0
	adminBan := admin
	adminBan.IP = user.IP
	adminBan.GroupBy = user.GroupBy
	adminBan.GroupKey = user.GroupKey
	adminBan.BanUntil = &expires
	adminBan.EffectiveBanUntil = &expires
	adminBan.DecisionID = "startup-check"
	adminBan.DecisionRevision = 1
	adminObserved := adminBan
	adminObserved.ObserveOnly = true
	adminObserved.DecisionID = ""
	adminObserved.DecisionRevision = 0

	return []model.Incident{
		user,
		admin,
		banned,
		observed,
		adminBan,
		adminObserved,
	}
}
