package domain

// Verdict is an auditor's judgment on an EvidenceBundle.
type Verdict struct {
	Verdict    string   `json:"verdict"` // "valid" or "invalid"
	Checks     []string `json:"checks"`
	AuditorAns string   `json:"auditorAns"`
}
