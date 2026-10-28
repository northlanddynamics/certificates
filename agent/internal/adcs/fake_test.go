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
	fake.SetTemplate(adcs.Template{
		Name: "CorpWebServerApproved", OID: "1.3.6.1.4.1.311.21.8.1.4", DisplayName: "Corp Web Server (approved)", ExtendedKeyUsages: []string{"1.3.6.1.5.5.7.3.1"},
		ValidityDays: 365, MinimumKeySize: 2048, KeyAlgorithms: []string{"rsa"}, ManagerApproval: true, SubjectFromRequest: true, Enrollable: true, Published: true,
	})
	adcstest.Run(t, adcstest.Lab{
		Client:            fake,
		ConfigString:      `ca01.corp.example\Corp Issuing CA`,
		UnknownCA:         `ca01.corp.example\No Such CA`,
		Unreachable:       `ca99.corp.example\Corp Issuing CA`,
		SuppliedTemplate:  "CorpWebServer",
		DirectoryTemplate: "Workstation",
		ApprovalTemplate:  "CorpWebServerApproved",
		Name:              "contract.corp.example",
		Manager:           fake,
	})
}
