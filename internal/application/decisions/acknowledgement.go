package decisions

// Acknowledgement identifies the last successfully delivered decision revision.
type Acknowledgement struct {
	// Destination identifies the configured provider instance.
	Destination string `json:"destination" yaml:"destination"`
	// Revision is the latest revision acknowledged by this destination.
	Revision int64 `json:"acknowledgedRevision" yaml:"acknowledgedRevision"`
}
