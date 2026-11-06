package config

// ProviderKind identifies the implementation used by an action target.
type ProviderKind string

const (
	// ProviderWebhook sends signed decision notifications.
	ProviderWebhook ProviderKind = "webhook"
	// ProviderCloudflare manages Cloudflare zone access rules.
	ProviderCloudflare ProviderKind = "cloudflare"
)

// Valid reports whether kind identifies a supported action provider.
func (kind ProviderKind) Valid() bool {
	switch kind {
	case ProviderWebhook, ProviderCloudflare:
		return true
	default:
		return false
	}
}
