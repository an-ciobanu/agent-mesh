package domain

// MandateClaims is the JSON payload inside a signed mandate (a COSE_Sign1). A
// mandate authorizes SubjectAns to interact with AudienceAns within Scope for a
// validity window, attested by AuthorityAns. Binding the mandate to the caller's
// key (sender-constraint via DPoP) is deferred to a later phase.
type MandateClaims struct {
	MandateID    string `json:"mandateId"`
	SubjectAns   string `json:"subjectAns"`
	AudienceAns  string `json:"audienceAns"`
	Scope        string `json:"scope"`
	NotBefore    string `json:"notBefore"`
	NotAfter     string `json:"notAfter"`
	AuthorityAns string `json:"authorityAns"`
}
