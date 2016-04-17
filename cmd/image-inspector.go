package main

import (
	"flag"
	"fmt"
	"log"

	iicmd "github.com/simon3z/image-inspector/pkg/cmd"
	ii "github.com/simon3z/image-inspector/pkg/inspector"
)

func main() {
	inspectorOptions := iicmd.NewDefaultImageInspectorOptions()

	flag.StringVar(&inspectorOptions.URI, "docker", inspectorOptions.URI, "Daemon socket to connect to")
	flag.StringVar(&inspectorOptions.Image, "image", inspectorOptions.Image, "Docker image to inspect")
	flag.StringVar(&inspectorOptions.DstPath, "path", inspectorOptions.DstPath, "Destination path for the image files")
	flag.StringVar(&inspectorOptions.Serve, "serve", inspectorOptions.Serve, "Host and port where to serve the image with webdav")
	flag.BoolVar(&inspectorOptions.Chroot, "chroot", inspectorOptions.Chroot, "Change root when serving the image with webdav")
	flag.StringVar(&inspectorOptions.DockerCfg, "dockercfg", inspectorOptions.DockerCfg, "Location of the docker configuration file")
	flag.StringVar(&inspectorOptions.Username, "username", inspectorOptions.Username, "username for authenticating with the docker registry")
	flag.StringVar(&inspectorOptions.PasswordFile, "password-file", inspectorOptions.PasswordFile, "Location of a file that contains the password for authentication with the docker registry")
	flag.StringVar(&inspectorOptions.ServerAuthType, "server-auth-type", inspectorOptions.ServerAuthType, fmt.Sprintf("The type of authentication to be used with the image server, possible values are %v", iicmd.ServerAuthOptions))

	flag.Parse()

	if err := inspectorOptions.Validate(); err != nil {
		log.Fatal(err)
	}

	inspector := ii.NewDefaultImageInspector(*inspectorOptions)
	if err := inspector.Inspect(); err != nil {
		log.Fatalf("Error inspecting image: %v", err)
	}
}
