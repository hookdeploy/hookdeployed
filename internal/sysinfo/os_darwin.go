//go:build darwin

package sysinfo

import (
	"context"
	"os/exec"
	"time"
)

const swVersTimeout = 2 * time.Second

func osVersion() string {
	ctx, cancel := context.WithTimeout(context.Background(), swVersTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "sw_vers")
	out, err := cmd.Output()
	if err != nil {
		return ""
	}
	return parseSwVers(out)
}
