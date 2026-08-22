//go:build !linux && !darwin && !windows

package sysinfo

func osVersion() string {
	return ""
}
