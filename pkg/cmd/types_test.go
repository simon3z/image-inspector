package cmd

import (
	"testing"
)

func TestValidate(t *testing.T) {
	noURI := NewDefaultImageInspectorOptions()
	noURI.URI = ""

	dockerCfgAndUsername := NewDefaultImageInspectorOptions()
	dockerCfgAndUsername.DockerCfg = "foo"
	dockerCfgAndUsername.Username = "bar"

	usernameNoPasswordFile := NewDefaultImageInspectorOptions()
	usernameNoPasswordFile.Username = "foo"

	noServeAndChroot := NewDefaultImageInspectorOptions()
	noServeAndChroot.Chroot = true

	goodConfigUsername := NewDefaultImageInspectorOptions()
	goodConfigUsername.URI = "uri"
	goodConfigUsername.Image = "image"
	goodConfigUsername.Username = "username"
	goodConfigUsername.PasswordFile = "password"

	goodConfigWithDockerCfg := NewDefaultImageInspectorOptions()
	goodConfigWithDockerCfg.URI = "uri"
	goodConfigWithDockerCfg.Image = "image"
	goodConfigWithDockerCfg.DockerCfg = "docker"

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
