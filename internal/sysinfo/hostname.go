package sysinfo

import "os"

func hostname() (string, error) {
	return os.Hostname()
}
