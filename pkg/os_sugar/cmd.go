package os_sugar

import (
	"os/exec"
	"strings"
)

func HasBinary(executable string) bool {
	if path, err := exec.LookPath(executable); err != nil || path == "" {
		return false
	}
	return true
}

func Exec(executable string, args []string) (string, error) {
	path, err := exec.LookPath(executable)
	if err != nil {
		return "", err
	}

	raw, err := exec.Command(path, args...).CombinedOutput()
	if err != nil {
		return strings.TrimSpace(string(raw)), err
	} else {
		return strings.TrimSpace(string(raw)), nil
	}
}
