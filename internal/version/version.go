package version

// Version is the agent release string. Release builds override it:
//
//	-ldflags "-X github.com/hookdeploy/hookdeployed/internal/version.Version=0.1.0"
//
// Unset / local builds stay "dev".
var Version = "dev"
