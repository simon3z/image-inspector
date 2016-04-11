package imageserver

import (
	docker "github.com/fsouza/go-dockerclient"
)

// ImageServer abstracts the serving of image information.
type ImageServer interface {
	// ServeImage Serves the image
	ServeImage(imageMetadata *docker.Image) error
}

// APIVersions holds a slice of supported API versions.
type APIVersions struct {
	// Versions is the supported API versions
	Versions []string `json:"versions"`
}

// ImageServerOptions is used to configure an image server.
type ImageServerOptions struct {
	// ServePath is the root path/port of serving. ex 0.0.0.0:8080
	ServePath string
	// HealthzURL is the relative url of the health check. ex /healthz
	HealthzURL string
	// APIURL is the relative url where the api will be served.  ex /api
	APIURL string
	// APIVersions are the supported API versions.
	APIVersions APIVersions
	// MetadataURL is the relative url of the metadata content.  ex /api/v1/metadata
	MetadataURL string
	// ContentURL is the relative url of the content.  ex /api/v1/content/
	ContentURL string
	// ImageServeURL is the location that the image is being served from.
	// NOTE: if the image server supports a chroot the server implementation will perform
	// the chroot based on this URL.
	ImageServeURL string
}
