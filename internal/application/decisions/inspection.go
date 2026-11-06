package decisions

// Inspection combines the latest desired state with delivery acknowledgements.
type Inspection struct {
	// Decision contains the effective desired state for the address.
	Decision Decision `json:"decision"`
	// Deliveries records each destination’s acknowledged revision.
	Deliveries []Acknowledgement `json:"deliveries"`
}

// Acknowledgement identifies the last successfully delivered revision.
type Acknowledgement struct {
	// Destination identifies the configured provider instance.
	Destination string `json:"destination"`
	// Revision is the latest revision acknowledged by this destination.
	Revision int64 `json:"acknowledgedRevision"`
}
