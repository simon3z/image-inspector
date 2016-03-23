package cmd

import (
	"testing"
)

func TestValidate(t *testing.T) {
	noURI := NewDefaultImageInspectorOptions()
	noURI.URI = ""

	dockerCfgAndUsername := NewDefaultImageInspectorOptions()
	dockerCfgAndUsername.Image = "image"
	dockerCfgAndUsername.DockerCfg = "foo"
	dockerCfgAndUsername.Username = "bar"

	usernameNoPasswordFile := NewDefaultImageInspectorOptions()
	usernameNoPasswordFile.Image = "image"
	usernameNoPasswordFile.Username = "foo"

	noServeAndChroot := NewDefaultImageInspectorOptions()
	noServeAndChroot.Image = "image"
	noServeAndChroot.Chroot = true

	goodConfigUsername := NewDefaultImageInspectorOptions()
	goodConfigUsername.Image = "image"
	goodConfigUsername.Username = "username"
	goodConfigUsername.PasswordFile = "types.go"

	goodConfigWithDockerCfg := NewDefaultImageInspectorOptions()
	goodConfigWithDockerCfg.Image = "image"
	goodConfigWithDockerCfg.DockerCfg = "types.go"

	noScanTypeAndDir := NewDefaultImageInspectorOptions()
	noScanTypeAndDir.Image = "image"
	noScanTypeAndDir.ScanResultsDir = "/tmp"

	goodScanOptions := NewDefaultImageInspectorOptions()
	goodScanOptions.Image = "image"
	goodScanOptions.ScanType = "openscap"
	goodScanOptions.ScanResultsDir = "."

	notADirResScan := NewDefaultImageInspectorOptions()
	notADirResScan.Image = "image"
	notADirResScan.ScanType = "openscap"
	notADirResScan.ScanResultsDir = "types_test.go"

	noSuchScanType := NewDefaultImageInspectorOptions()
	noSuchScanType.Image = "image"
	noSuchScanType.ScanType = "nosuchscantype"
	noSuchScanType.ScanResultsDir = "."

	noSuchFileDockercfg := NewDefaultImageInspectorOptions()
	noSuchFileDockercfg.Image = "image"
	noSuchFileDockercfg.DockerCfg = "nosuchfile"

	tests := map[string]struct {
		inspector      *ImageInspectorOptions
		shouldValidate bool
	}{
		"no uri":                        {inspector: noURI, shouldValidate: false},
		"no image":                      {inspector: NewDefaultImageInspectorOptions(), shouldValidate: false},
		"docker config and username":    {inspector: dockerCfgAndUsername, shouldValidate: false},
		"username and no password file": {inspector: usernameNoPasswordFile, shouldValidate: false},
		"no serve and chroot":           {inspector: noServeAndChroot, shouldValidate: false},
		"good config with username":     {inspector: goodConfigUsername, shouldValidate: true},
		"good config with docker cfg":   {inspector: goodConfigWithDockerCfg, shouldValidate: true},
		"no scan-type with scan-dir":    {inspector: noScanTypeAndDir, shouldValidate: false},
		"no such file dockercfg":        {inspector: noSuchFileDockercfg, shouldValidate: false},
		"no such scan type available":   {inspector: noSuchScanType, shouldValidate: false},
		"file exists and is not a dir":  {inspector: notADirResScan, shouldValidate: false},
		"good config with scan options": {inspector: goodScanOptions, shouldValidate: true},
	}

	for k, v := range tests {
		err := v.inspector.Validate()

		if v.shouldValidate && err != nil {
			t.Errorf("%s expected to validate but received %v", k, err)
		}
		if !v.shouldValidate && err == nil {
			t.Errorf("%s expected to be invalid but received no error", k)
		}
	}
}
