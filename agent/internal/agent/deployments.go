package agent

import (
	"context"
	"encoding/json"
	"path/filepath"
	"time"

	"certificate-platform/agent/internal/deploy"
	"certificate-platform/agent/internal/keystore"
	"certificate-platform/agent/internal/platform"
)

// The work item types by which the platform has the Agent make a key for a Managed Certificate and run a Deployment Script.
const (
	workGenerateKey = "deployment.generate_key"
	workRun         = "deployment.run"
)

// keyWork is what a `deployment.generate_key` work item carries.
type keyWork struct {
	ManagedCertificateID string   `json:"managedCertificateId"`
	Names                []string `json:"names"`
	KeyAlgorithm         string   `json:"keyAlgorithm"`
}

// decode reads a work item's payload into v.
func decode(item platform.WorkItem, v any) error {
	data, err := json.Marshal(item.Payload)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, v)
}

func (r *runner) keys() keystore.Store {
	return keystore.Store{Dir: filepath.Join(r.cfg.StateDir, "keys")}
}

// generateKey makes the key here and reports a CSR for it: the key itself goes nowhere (ADR 0002).
func (r *runner) generateKey(item platform.WorkItem) platform.WorkResult {
	var work keyWork
	if err := decode(item, &work); err != nil {
		return platform.WorkResult{Error: "the work item does not describe a key to make"}
	}
	csr, err := r.keys().Generate(work.ManagedCertificateID, work.KeyAlgorithm, work.Names)
	if err != nil {
		r.cfg.Log.Warn("a key could not be made", "id", item.ID, "error", err)
		return platform.WorkResult{Error: "the Agent could not make the key: " + err.Error()}
	}
	r.cfg.Log.Info("made a key and a CSR for it", "id", item.ID, "managedCertificateId", work.ManagedCertificateID, "algorithm", work.KeyAlgorithm)
	return platform.WorkResult{OK: true, CSR: string(csr)}
}

// runDeployment runs the Deployment Script for the Certificate the work item carries, if the checks on it pass.
func (r *runner) runDeployment(ctx context.Context, item platform.WorkItem) platform.WorkResult {
	var work deploy.Work
	if err := decode(item, &work); err != nil {
		return platform.WorkResult{Error: "the work item does not describe a Deployment to run"}
	}
	runner := deploy.Runner{Keys: r.keys(), StateDir: r.cfg.StateDir, Now: r.cfg.Clock.Now, Timeout: r.cfg.ScriptTimeout}
	res := runner.Run(ctx, work)
	report := &platform.RunReport{
		StartedAt:       res.StartedAt.UTC().Format(time.RFC3339),
		FinishedAt:      res.FinishedAt.UTC().Format(time.RFC3339),
		ExitCode:        res.ExitCode,
		Output:          res.Output,
		OutputTruncated: res.OutputTruncated,
	}
	// The script and its output are not logged: only that it ran, and how it ended.
	if res.OK() {
		r.cfg.Log.Info("ran a Deployment Script", "id", item.ID, "deploymentId", work.DeploymentID)
		return platform.WorkResult{OK: true, Run: report}
	}
	failure := "the script was not run"
	if res.ExitCode != nil {
		failure = "the script did not succeed"
	}
	r.cfg.Log.Warn("a Deployment Script did not succeed", "id", item.ID, "deploymentId", work.DeploymentID, "exitCode", res.ExitCode)
	return platform.WorkResult{Error: failure, Run: report}
}
