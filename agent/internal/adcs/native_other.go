//go:build !windows

package adcs

// Native is the host's ADCS client. MS-WCCE is reached only from Windows, so off Windows there is none.
func Native() (Client, error) {
	return nil, Refused("this Agent cannot reach ADCS: it does not run on Windows")
}
