package agent

import (
	"context"
	"encoding/pem"

	"certificate-platform/agent/internal/adcs"
	"certificate-platform/agent/internal/platform"
)

// The work item types by which the platform has the Agent discover an ADCS CA, and submit a request to it, as its own account.
const (
	workDiscover = "adcs.discover"
	workSubmit   = "adcs.submit"
)

// adcsWork is what an ADCS work item carries. It holds no secret: the Agent reaches ADCS as itself. Template and CSR (PEM)
// are for a submission.
type adcsWork struct {
	ConfigString string `json:"configString"`
	Template     string `json:"template"`
	CSR          string `json:"csr"`
}

// adcsClient is how the Agent reaches ADCS: the one it was given, or the host's.
func (r *runner) adcsClient() (adcs.Client, error) {
	if r.cfg.ADCS != nil {
		return r.cfg.ADCS, nil
	}
	return adcs.Native()
}

// adcsFailed reports an ADCS operation that did not succeed.
func (r *runner) adcsFailed(item platform.WorkItem, err error) platform.WorkResult {
	failure := adcs.AsError(err)
	r.cfg.Log.Warn("an ADCS operation failed", "id", item.ID, "type", item.Type, "kind", failure.Kind, "error", failure.Message)
	return platform.WorkResult{Kind: failure.Kind, Error: failure.Message}
}

// discover fetches the CA's chain and lists its templates.
func (r *runner) discover(ctx context.Context, item platform.WorkItem) platform.WorkResult {
	var work adcsWork
	if err := decode(item, &work); err != nil || work.ConfigString == "" {
		return r.adcsFailed(item, adcs.Refused("the work item does not name an ADCS CA"))
	}
	client, err := r.adcsClient()
	if err != nil {
		return r.adcsFailed(item, err)
	}
	chain, err := client.Chain(ctx, work.ConfigString)
	if err != nil {
		return r.adcsFailed(item, err)
	}
	templates, err := client.Discover(ctx, work.ConfigString)
	if err != nil {
		return r.adcsFailed(item, err)
	}
	discovery := &platform.Discovery{Chain: make([]string, len(chain)), Templates: make([]platform.Template, len(templates))}
	for i, der := range chain {
		discovery.Chain[i] = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	}
	for i, t := range templates {
		discovery.Templates[i] = platform.Template{
			Name: t.Name, OID: t.OID, DisplayName: t.DisplayName, ExtendedKeyUsages: nonNil(t.ExtendedKeyUsages), ValidityDays: t.ValidityDays,
			MinimumKeySize: t.MinimumKeySize, KeyAlgorithms: nonNil(t.KeyAlgorithms), ManagerApproval: t.ManagerApproval,
			SubjectFromRequest: t.SubjectFromRequest, Enrollable: t.Enrollable, Published: t.Published,
		}
	}
	r.cfg.Log.Info("discovered an ADCS CA", "id", item.ID, "configString", work.ConfigString, "templates", len(templates))
	return platform.WorkResult{OK: true, Discovery: discovery}
}

// submit submits the CSR to the CA under the template, and reports what ADCS answered.
func (r *runner) submit(ctx context.Context, item platform.WorkItem) platform.WorkResult {
	var work adcsWork
	if err := decode(item, &work); err != nil || work.ConfigString == "" || work.Template == "" {
		return r.adcsFailed(item, adcs.Refused("the work item does not name an ADCS CA and a template"))
	}
	block, _ := pem.Decode([]byte(work.CSR))
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		return r.adcsFailed(item, adcs.Refused("the work item carries no CSR"))
	}
	client, err := r.adcsClient()
	if err != nil {
		return r.adcsFailed(item, err)
	}
	submission, err := client.Submit(ctx, work.ConfigString, work.Template, block.Bytes)
	if err != nil {
		return r.adcsFailed(item, err)
	}
	r.cfg.Log.Info("submitted a request to an ADCS CA", "id", item.ID, "configString", work.ConfigString, "template", work.Template, "status", submission.Status, "requestId", submission.RequestID)
	return platform.WorkResult{OK: true, Submission: &platform.Submission{
		Status:      submission.Status,
		RequestID:   submission.RequestID,
		Certificate: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: submission.Certificate})),
	}}
}

// nonNil is a list as JSON has it: empty, never null.
func nonNil(list []string) []string {
	if list == nil {
		return []string{}
	}
	return list
}
