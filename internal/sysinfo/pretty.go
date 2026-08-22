package sysinfo

import (
	"bytes"
	"strings"
)

func parseSwVers(out []byte) string {
	name := ""
	version := ""
	for _, line := range bytes.Split(out, []byte("\n")) {
		key, value, ok := strings.Cut(string(line), ":")
		if !ok {
			continue
		}
		value = strings.TrimSpace(value)
		switch strings.TrimSpace(key) {
		case "ProductName":
			name = value
		case "ProductVersion":
			version = value
		}
	}
	return formatDarwinVersion(name, version)
}

func formatDarwinVersion(productName, productVersion string) string {
	name := strings.TrimSpace(productName)
	ver := strings.TrimSpace(productVersion)
	switch {
	case name == "" && ver == "":
		return ""
	case name == "":
		return ver
	case ver == "":
		return name
	default:
		return name + " " + ver
	}
}

func formatWindowsVersion(productName, displayVersion string) string {
	name := strings.TrimSpace(productName)
	display := strings.TrimSpace(displayVersion)
	if name == "" {
		return display
	}
	if display == "" || strings.Contains(name, display) {
		return name
	}
	return name + " " + display
}
