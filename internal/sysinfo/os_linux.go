//go:build linux

package sysinfo

import "os"

func osVersion() string {
	raw, err := os.ReadFile("/etc/os-release")
	if err != nil {
		return ""
	}
	return ParseOSRelease(string(raw))
}
