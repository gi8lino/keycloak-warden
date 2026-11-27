package model

// ChangeCause identifies the application workflow that revised a decision.
type ChangeCause string

const (
	// ChangeAutomatic identifies a revision caused by failed-login detection.
	ChangeAutomatic ChangeCause = "automatic"
	// ChangeManual identifies a revision caused by a manual ban.
	ChangeManual ChangeCause = "manual"
	// ChangeRelease identifies a revision caused by a manual unban.
	ChangeRelease ChangeCause = "release"
	// ChangeExpiry identifies a revision caused by expired ban sources.
	ChangeExpiry ChangeCause = "expiry"
	// ChangeReconciled identifies a revision caused by decision reconciliation.
	ChangeReconciled ChangeCause = "reconciled"
)
