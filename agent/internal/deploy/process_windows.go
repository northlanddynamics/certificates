//go:build windows

package deploy

import "os/exec"

// setProcessGroup does nothing on Windows: the process is killed when it times out.
func setProcessGroup(cmd *exec.Cmd) {}
