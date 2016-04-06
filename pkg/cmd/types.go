package cmd

import (
	"fmt"
)

// ImageInspectorOptions is the main inspector implementation and holds the configuration
// for an image inspector.
type ImageInspectorOptions struct {
	// URI contains the location of the docker daemon socket to connect to.
	URI string
	// Image contains the docker image to inspect.
	Image string
	// DstPath is the destination path for image files.
	DstPath string
	// Serve holds the host and port for where to serve the image with webdav.
	Serve string
	// Chroot controls whether or not a chroot is excuted when serving the image with webdav.
	Chroot bool
	// DockerCfg is the location of the docker config file.
	DockerCfg string
	// Username is the username for authenticating to the docker registry.
	Username string
	// PasswordFile is the location of the file containing the password for authentication to the
	// docker registry.
	PasswordFile string
}

// NewDefaultImageInspectorOptions provides a new ImageInspectorOptions with default values.
func NewDefaultImageInspectorOptions() *ImageInspectorOptions {
	return &ImageInspectorOptions{
		URI:          "unix:///var/run/docker.sock",
		Image:        "",
		DstPath:      "",
		Serve:        "",
		Chroot:       false,
		DockerCfg:    "",
		Username:     "",
		PasswordFile: "",
	}
}

// Validate performs validation on the field settings.
func (i *ImageInspectorOptions) Validate() error {
	if len(i.URI) == 0 {
		return fmt.Errorf("Docker socket connection must be specified")
	}
	if len(i.Image) == 0 {
		return fmt.Errorf("Docker image to inspect must be specified")
	}
	if len(i.DockerCfg) > 0 && len(i.Username) > 0 {
		return fmt.Errorf("Only specify dockercfg file or username/password pair for authentication")
	}
	if len(i.Username) > 0 && len(i.PasswordFile) == 0 {
		return fmt.Errorf("Please specify password for the username")
	}
	if len(i.Serve) == 0 && i.Chroot {
		return fmt.Errorf("Change root can be used only when serving the image through webdav")
	}
	return nil
}
