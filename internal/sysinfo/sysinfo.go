package sysinfo

import (
	"runtime"

	"github.com/hookdeploy/hookdeployed/internal/version"
)

// Info is the payload sent to POST /v1/agents/system-info.
// OS is runtime.GOOS (linux|darwin|windows). Arch is runtime.GOARCH.
type Info struct {
	Hostname     string `json:"hostname"`
	OS           string `json:"os"`
	OSVersion    string `json:"os_version"`
	Arch         string `json:"arch"`
	AgentVersion string `json:"agent_version"`
}

// Collect gathers host fields. Individual collectors must not panic or
// block indefinitely; a missing file or failed probe yields an empty
// os_version. Hostname errors yield "".
func Collect() Info {
	hostname, err := hostname()
	if err != nil {
		hostname = ""
	}
	return Info{
		Hostname:     hostname,
		OS:           runtime.GOOS,
		OSVersion:    osVersion(),
		Arch:         runtime.GOARCH,
		AgentVersion: version.Version,
	}
}

func (a Info) equal(b Info) bool {
	return a.Hostname == b.Hostname &&
		a.OS == b.OS &&
		a.OSVersion == b.OSVersion &&
		a.Arch == b.Arch &&
		a.AgentVersion == b.AgentVersion
}
