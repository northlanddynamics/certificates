package agent

import (
	"context"
	"encoding/pem"

	"certificate-platform/agent/internal/adcs"
	"certificate-platform/agent/internal/platform"
)

// The work item type by which the platform has the Agent discover an ADCS CA, as its own account.
const workDiscover = "adcs.discover"

// adcsWork is what an ADCS work item carries. It holds no secret: the Agent reaches ADCS as itself.
type adcsWork struct {
	ConfigString string `json:"configString"`
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

// nonNil is a list as JSON has it: empty, never null.
func nonNil(list []string) []string {
	if list == nil {
		return []string{}
	}
	return list
}
