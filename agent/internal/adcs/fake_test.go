package adcs_test

import (
	"testing"

	"certificate-platform/agent/internal/adcs"
	"certificate-platform/agent/internal/adcs/adcstest"
)

func TestTheFakeKeepsTheContract(t *testing.T) {
	fake, err := adcs.NewFake(`ca01.corp.example\Corp Issuing CA`)
	if err != nil {
		t.Fatal(err)
	}
	adcstest.Run(t, adcstest.Lab{
		Client:            fake,
		ConfigString:      `ca01.corp.example\Corp Issuing CA`,
		UnknownCA:         `ca01.corp.example\No Such CA`,
		Unreachable:       `ca99.corp.example\Corp Issuing CA`,
		SuppliedTemplate:  "CorpWebServer",
		DirectoryTemplate: "Workstation",
	})
}
