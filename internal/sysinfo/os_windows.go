//go:build windows

package sysinfo

import (
	"golang.org/x/sys/windows/registry"
)

func osVersion() string {
	key, err := registry.OpenKey(
		registry.LOCAL_MACHINE,
		`SOFTWARE\Microsoft\Windows NT\CurrentVersion`,
		registry.QUERY_VALUE|registry.WOW64_64KEY,
	)
	if err != nil {
		return ""
	}
	defer key.Close()

	productName, _, _ := key.GetStringValue("ProductName")
	displayVersion, _, _ := key.GetStringValue("DisplayVersion")
	return formatWindowsVersion(productName, displayVersion)
}
