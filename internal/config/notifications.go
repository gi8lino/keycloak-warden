package config

import (
	"fmt"

	"github.com/gi8lino/keycloak-warden/internal/application/detection"
)

// Notifications groups named incident webhook endpoints.
type Notifications struct {
	// Delivery contains the shared webhook and retry settings.
	Delivery `yaml:",inline"`
}

// Validate checks destination structures and every rule's notification references.
func (n Notifications) Validate(rules detection.Rules) error {
	if err := n.validate("notifications"); err != nil {
		return err
	}

	for _, rule := range rules.Ordered() {
		seen := make(map[string]struct{})
		for _, name := range rule.Actions.Notify {
			if _, ok := n.Webhook[name]; !ok {
				return fmt.Errorf("rule %q: unknown notification destination %q", rule.Name, name)
			}
			if _, ok := seen[name]; ok {
				return fmt.Errorf("rule %q: duplicate notification destination %q", rule.Name, name)
			}
			seen[name] = struct{}{}
		}
	}
	return nil
}
