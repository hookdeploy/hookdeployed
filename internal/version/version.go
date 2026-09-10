package version

// Version is the agent release string. Release builds override it:
//
//	-ldflags "-X github.com/hookdeploy/hookdeployed/internal/version.Version=0.1.3"
//
// Unset / local builds use this default.
var Version = "0.1.3"
