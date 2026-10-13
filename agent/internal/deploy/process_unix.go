//go:build !windows

package deploy

import (
	"os/exec"
	"syscall"
)

// setProcessGroup has the script's processes stopped together when it times out, so that what it started does not outlive it.
func setProcessGroup(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
}
