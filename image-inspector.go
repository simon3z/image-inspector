package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"math"
	"math/big"
	"net/http"
	"os"
	"path"
	"strings"

	"archive/tar"
	"crypto/rand"

	docker "github.com/fsouza/go-dockerclient"
	"golang.org/x/net/webdav"
)

type APIVersions struct {
	Versions []string `json:"versions"`
}

const (
	VERSION_TAG        = "v1"
	DOCKER_TAR_PREFIX  = "rootfs/"
	OWNER_PERM_RW      = 0600
	HEALTHZ_URL_PATH   = "/healthz"
	API_URL_PREFIX     = "/api"
	CONTENT_URL_PREFIX = API_URL_PREFIX + "/" + VERSION_TAG + "/content/"
	METADATA_URL_PATH  = API_URL_PREFIX + "/" + VERSION_TAG + "/metadata"
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

		dstpath := path.Join(destination, strings.TrimPrefix(hdr.Name, DOCKER_TAR_PREFIX))
		// Overriding permissions to allow writing content
		mode := hdrInfo.Mode() | OWNER_PERM_RW

		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.Mkdir(dstpath, mode); err != nil {
				if !os.IsExist(err) {
					return fmt.Errorf("Unable to create directory: %v", err)
				}
				err = os.Chmod(dstpath, mode)
				if err != nil {
					return fmt.Errorf("Unable to update directory mode: %v", err)
				}
			}
		case tar.TypeReg, tar.TypeRegA:
			file, err := os.OpenFile(dstpath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, mode)
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

		// maintaining access and modification time in best effort fashion
		os.Chtimes(dstpath, hdr.AccessTime, hdr.ModTime)
	}
}

func generateRandomName() string {
	n, err := rand.Int(rand.Reader, big.NewInt(math.MaxInt64))
	if err != nil {
		log.Fatalf("Unable to generate random container name: %v\n", err)
	}
	return fmt.Sprintf("image-inspector-%016x", n)
}

func getAuthConfigs(dockercfg, username, password_file *string) *docker.AuthConfigurations {
	imagePullAuths := &docker.AuthConfigurations{
		map[string]docker.AuthConfiguration{"": docker.AuthConfiguration{}}}
	if *dockercfg != "" {
		reader, err := os.Open(*dockercfg)
		if err != nil {
			log.Fatalf("Unable to open docker config file: %v\n", err)
		}
		if imagePullAuths, err = docker.NewAuthConfigurations(reader); err != nil {
			log.Fatalf("Unable to parse docker config file: %v\n", err)
		}
		if len(imagePullAuths.Configs) == 0 {
			log.Fatalf("No auths were found in the given dockercfg file\n")
		}
	}
	if *username != "" {
		token, err := ioutil.ReadFile(*password_file)
		if err != nil {
			log.Fatalf("Unable to read password file: %v\n", err)
		}
		imagePullAuths = &docker.AuthConfigurations{
			map[string]docker.AuthConfiguration{"": docker.AuthConfiguration{Username: *username, Password: string(token)}}}
	}

	return imagePullAuths
}

func main() {
	uri := flag.String("docker", "unix:///var/run/docker.sock", "Daemon socket to connect to")
	image := flag.String("image", "", "Docker image to inspect")
	dstpath := flag.String("path", "", "Destination path for the image files")
	serve := flag.String("serve", "", "Host and port where to serve the image with webdav")
	dockercfg := flag.String("dockercfg", "", "Location of the docker configuration file")
	username := flag.String("username", "", "username for authenticating with the docker registry")
	password_file := flag.String("password-file", "", "Location of a file that contains the password for authentication with the docker registry")

	flag.Parse()

	if *uri == "" {
		log.Fatalln("Docker socket connection must be specified")
	}
	if *image == "" {
		log.Fatalln("Docker image to inspect must be specified")
	}
	if *dockercfg != "" && *username != "" {
		log.Fatalln("Only specify dockercfg file or username/password pair for authentication")
	}
	if *username != "" && *password_file == "" {
		log.Fatalln("Please specify password for the username")
	}

	client, err := docker.NewClient(*uri)
	if err != nil {
		log.Fatalf("Unable to connect to docker daemon: %v\n", err)
	}

	if _, err := client.InspectImage(*image); err != nil {
		log.Printf("Pulling image %s", *image)
		imagePullOption := docker.PullImageOptions{Repository: *image}
		imagePullAuths := getAuthConfigs(dockercfg, username, password_file)
		// Try all the possible auth's from the config file
		var authErr error
		for _, auth := range imagePullAuths.Configs {
			if authErr = client.PullImage(imagePullOption, auth); authErr == nil {
				break
			}
		}
		if authErr != nil {
			log.Fatalf("Unable to pull docker image: %v\n", authErr)
		}
	} else {
		log.Printf("Image %s is available, skipping image pull", *image)
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

	if dstpath != nil && *dstpath != "" {
		err = os.Mkdir(*dstpath, 0755)
		if err != nil {
			if !os.IsExist(err) {
				log.Fatalf("Unable to create destination path: %v\n", err)
			}
		}
	} else {
		// forcing to use /var/tmp because often it's not an in-memory tmpfs
		*dstpath, err = ioutil.TempDir("/var/tmp", "image-inspector-")
		if err != nil {
			log.Fatalf("Unable to create temporary path: %v\n", err)
		}
	}

	reader, writer := io.Pipe()
	go handleTarStream(reader, *dstpath)

	log.Printf("Extracting image %s to %s", *image, *dstpath)
	err = client.CopyFromContainer(docker.CopyFromContainerOptions{
		Container:    container.ID,
		OutputStream: writer,
		Resource:     "/",
	})
	if err != nil {
		log.Fatalf("Unable to extract container: %v\n", err)
	}

	_ = client.RemoveContainer(docker.RemoveContainerOptions{
		ID: container.ID,
	})

	supportedVersions := APIVersions{Versions: []string{VERSION_TAG}}

	if *serve != "" {
		log.Printf("Serving image content %s on webdav://%s%s", *dstpath, *serve, CONTENT_URL_PREFIX)

		http.HandleFunc(HEALTHZ_URL_PATH, func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte("ok\n"))
		})

		http.HandleFunc(API_URL_PREFIX, func(w http.ResponseWriter, r *http.Request) {
			body, err := json.MarshalIndent(supportedVersions, "", "  ")
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			w.Write(body)
		})

		http.HandleFunc(METADATA_URL_PATH, func(w http.ResponseWriter, r *http.Request) {
			body, err := json.MarshalIndent(imageMetadata, "", "  ")
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			w.Write(body)
		})

		http.Handle(CONTENT_URL_PREFIX, &webdav.Handler{
			Prefix:     CONTENT_URL_PREFIX,
			FileSystem: webdav.Dir(*dstpath),
			LockSystem: webdav.NewMemLS(),
		})

		log.Fatal(http.ListenAndServe(*serve, nil))
	}
}
