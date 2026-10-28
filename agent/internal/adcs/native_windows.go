//go:build windows

package adcs

// Native is the host's ADCS client, which speaks MS-WCCE through CertEnroll and CertCli. Until it is built, a Windows Agent
// cannot reach ADCS either.
func Native() (Client, error) {
	return nil, Refused("this Agent cannot reach ADCS: this build has no MS-WCCE client")
}
