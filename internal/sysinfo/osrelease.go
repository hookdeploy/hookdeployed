package sysinfo

import (
	"bufio"
	"strings"
)

// ParseOSRelease extracts PRETTY_NAME, or ID + VERSION_ID, from an
// /etc/os-release body. Empty input yields "".
func ParseOSRelease(contents string) string {
	pretty := ""
	id := ""
	versionID := ""
	scanner := bufio.NewScanner(strings.NewReader(contents))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		value = unquote(value)
		switch key {
		case "PRETTY_NAME":
			pretty = value
		case "ID":
			id = value
		case "VERSION_ID":
			versionID = value
		}
	}
	if pretty != "" {
		return pretty
	}
	if id == "" && versionID == "" {
		return ""
	}
	return strings.TrimSpace(id + " " + versionID)
}

func unquote(v string) string {
	v = strings.TrimSpace(v)
	if len(v) >= 2 {
		if (v[0] == '"' && v[len(v)-1] == '"') || (v[0] == '\'' && v[len(v)-1] == '\'') {
			return v[1 : len(v)-1]
		}
	}
	return v
}
