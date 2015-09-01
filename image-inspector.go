package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"math"
	"math/big"
	"net/http"
	"os"
	"path"
	"strings"

	"archive/tar"
	"crypto/rand"

	"github.com/fsouza/go-dockerclient"
	"golang.org/x/net/webdav"
)

const (
	DOCKER_TAR_PREFIX  = "rootfs/"
	OWNER_PERM_RW      = 0600
	VERSION_PREFIX     = "/v1"
	CONTENT_URL_PREFIX = VERSION_PREFIX + "/content/"
	METADATA_URL_PATH  = VERSION_PREFIX + "/metadata"
)

func handleTarStream(reader io.ReadCloser, destination string) {
	tr := tar.NewReader(reader)
	if tr != nil {
		err := processTarStream(tr, destination)
		if err != nil {
			log.Print(err)
		}
	} else {
		log.Printf("Unable to create image tar reader")
	}
	reader.Close()
}

func processTarStream(tr *tar.Reader, destination string) error {
	for {
		hdr, err := tr.Next()
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return fmt.Errorf("Unable to extract container: %v\n", err)
		}

		hdrInfo := hdr.FileInfo()

		path := path.Join(destination, strings.TrimPrefix(hdr.Name, DOCKER_TAR_PREFIX))
		// Overriding permissions to allow writing content
		mode := hdrInfo.Mode() | OWNER_PERM_RW

		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.Mkdir(path, mode); err != nil {
				if !os.IsExist(err) {
					return fmt.Errorf("Unable to create directory: %v", err)
				}
				err = os.Chmod(path, mode)
				if err != nil {
					return fmt.Errorf("Unable to update directory mode: %v", err)
				}
			}
		case tar.TypeReg, tar.TypeRegA:
			file, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, mode)
			if err != nil {
				return fmt.Errorf("Unable to create file: %v", err)
			}
			if _, err := io.Copy(file, tr); err != nil {
				file.Close()
				return fmt.Errorf("Unable to write into file: %v", err)
			}
			file.Close()
		default:
			// For now we're skipping anything else. Special device files and
			// symlinks are not needed or anyway probably incorrect.
		}
	}
}

func generateRandomName() string {
	n, err := rand.Int(rand.Reader, big.NewInt(math.MaxInt64))
	if err != nil {
		log.Fatalf("Unable to generate random container name: %v\n", err)
	}
	return fmt.Sprintf("image-inspector-%016x", n)
}

func main() {
	uri := flag.String("docker", "unix:///var/run/docker.sock", "Daemon socket to connect to")
	image := flag.String("image", "", "Docker image to inspect")
	path := flag.String("path", "", "Destination path for the image files")
	serve := flag.String("serve", "", "Host and port where to serve the image with webdav")

	flag.Parse()

	if *uri == "" {
		log.Fatalf("Docker socket connection must be specified")
	}
	if *image == "" {
		log.Fatalf("Docker image to inspect must be specified")
	}
	if *path == "" {
		log.Fatalf("Destination path for image files must be specified")
	}

	client, err := docker.NewClient(*uri)
	if err != nil {
		log.Fatalf("Unable to connect to docker daemon: %v\n", err)
	}

	log.Printf("Pulling image %s", *image)
	imagePullOption := docker.PullImageOptions{Repository: *image}
	imagePullAuth := docker.AuthConfiguration{} // TODO: support authentication
	if err := client.PullImage(imagePullOption, imagePullAuth); err != nil {
		log.Fatalf("Unable to pull docker image: %v\n", err)
	}

	// For security purpose we don't define any entrypoint and command
	container, err := client.CreateContainer(docker.CreateContainerOptions{
		Name: generateRandomName(),
		Config: &docker.Config{
			Image:      *image,
			Entrypoint: []string{""},
			Cmd:        []string{""},
		},
	})
	if err != nil {
		log.Fatalf("Unable to create docker container: %v\n", err)
	}

	containerMetadata, err := client.InspectContainer(container.ID)
	if err != nil {
		log.Fatalf("Unable to get docker container information: %v\n", err)
	}

	imageMetadata, err := client.InspectImage(containerMetadata.Image)
	if err != nil {
		log.Fatalf("Unable to get docker image information: %v\n", err)
	}

	err = os.Mkdir(*path, 0755)
	if err != nil {
		if !os.IsExist(err) {
			log.Fatalf("Unable to create destination path: %v\n", err)
		}
	}

	reader, writer := io.Pipe()
	go handleTarStream(reader, *path)

	log.Printf("Extracting image %s to %s", *image, *path)
	_ = client.CopyFromContainer(docker.CopyFromContainerOptions{
		Container:    container.ID,
		OutputStream: writer,
		Resource:     "/",
	})

	_ = client.RemoveContainer(docker.RemoveContainerOptions{
		ID: container.ID,
	})

	if serve != nil && *serve != "" {
		log.Printf("Serving image content %s on webdav://%s%s", *path, *serve, CONTENT_URL_PREFIX)

		http.Handle(CONTENT_URL_PREFIX, webdav.StripPrefix(CONTENT_URL_PREFIX, &webdav.Handler{
			FileSystem: webdav.Dir(*path),
			LockSystem: webdav.NewMemLS(),
		}))

		http.HandleFunc(METADATA_URL_PATH, func(w http.ResponseWriter, r *http.Request) {
			body, err := json.Marshal(imageMetadata)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			w.Write(body)
		})

		log.Fatal(http.ListenAndServe(*serve, nil))
	}
}
