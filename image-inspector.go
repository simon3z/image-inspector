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
	"syscall"

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
	CHROOT_SERVE_PATH  = "/"
)

// ImageInspectorOptions is the main inspector implementation (TODO - migrate most of main method
// into inspector methods so they can be tested outside of a main call) and holds the configuration
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
		case tar.TypeSymlink:
			if err := os.Symlink(hdr.Linkname, dstpath); err != nil {
				return fmt.Errorf("Unable to create symlink: %v\n", err)
			}
		case tar.TypeLink:
			target := path.Join(destination, strings.TrimPrefix(hdr.Linkname, DOCKER_TAR_PREFIX))
			if err := os.Link(target, dstpath); err != nil {
				return fmt.Errorf("Unable to create link: %v\n", err)
			}
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

func getAuthConfigs(dockercfg, username, password_file string) *docker.AuthConfigurations {
	imagePullAuths := &docker.AuthConfigurations{
		map[string]docker.AuthConfiguration{"": {}}}
	if dockercfg != "" {
		reader, err := os.Open(dockercfg)
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
	if username != "" {
		token, err := ioutil.ReadFile(password_file)
		if err != nil {
			log.Fatalf("Unable to read password file: %v\n", err)
		}
		imagePullAuths = &docker.AuthConfigurations{
			map[string]docker.AuthConfiguration{"": {Username: username, Password: string(token)}}}
	}

	return imagePullAuths
}

func main() {
	inspectorOptions := NewDefaultImageInspectorOptions()

	flag.StringVar(&inspectorOptions.URI, "docker", inspectorOptions.URI, "Daemon socket to connect to")
	flag.StringVar(&inspectorOptions.Image, "image", inspectorOptions.Image, "Docker image to inspect")
	flag.StringVar(&inspectorOptions.DstPath, "path", inspectorOptions.DstPath, "Destination path for the image files")
	flag.StringVar(&inspectorOptions.Serve, "serve", inspectorOptions.Serve, "Host and port where to serve the image with webdav")
	flag.BoolVar(&inspectorOptions.Chroot, "chroot", inspectorOptions.Chroot, "Change root when serving the image with webdav")
	flag.StringVar(&inspectorOptions.DockerCfg, "dockercfg", inspectorOptions.DockerCfg, "Location of the docker configuration file")
	flag.StringVar(&inspectorOptions.Username, "username", inspectorOptions.Username, "username for authenticating with the docker registry")
	flag.StringVar(&inspectorOptions.PasswordFile, "password-file", inspectorOptions.PasswordFile, "Location of a file that contains the password for authentication with the docker registry")

	flag.Parse()

	if err := inspectorOptions.Validate(); err != nil {
		log.Fatal(err)
	}

	client, err := docker.NewClient(inspectorOptions.URI)
	if err != nil {
		log.Fatalf("Unable to connect to docker daemon: %v\n", err)
	}

	if _, err := client.InspectImage(inspectorOptions.Image); err != nil {
		log.Printf("Pulling image %s", inspectorOptions.Image)
		imagePullOption := docker.PullImageOptions{Repository: inspectorOptions.Image}
		imagePullAuths := getAuthConfigs(inspectorOptions.DockerCfg, inspectorOptions.Username, inspectorOptions.PasswordFile)
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
		log.Printf("Image %s is available, skipping image pull", inspectorOptions.Image)
	}

	// For security purpose we don't define any entrypoint and command
	container, err := client.CreateContainer(docker.CreateContainerOptions{
		Name: generateRandomName(),
		Config: &docker.Config{
			Image:      inspectorOptions.Image,
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

	if len(inspectorOptions.DstPath) > 0 {
		err = os.Mkdir(inspectorOptions.DstPath, 0755)
		if err != nil {
			if !os.IsExist(err) {
				log.Fatalf("Unable to create destination path: %v\n", err)
			}
		}
	} else {
		// forcing to use /var/tmp because often it's not an in-memory tmpfs
		inspectorOptions.DstPath, err = ioutil.TempDir("/var/tmp", "image-inspector-")
		if err != nil {
			log.Fatalf("Unable to create temporary path: %v\n", err)
		}
	}

	reader, writer := io.Pipe()
	go handleTarStream(reader, inspectorOptions.DstPath)

	log.Printf("Extracting image %s to %s", inspectorOptions.Image, inspectorOptions.DstPath)
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

	if len(inspectorOptions.Serve) > 0 {
		servePath := inspectorOptions.DstPath
		if inspectorOptions.Chroot {
			if err := syscall.Chroot(inspectorOptions.DstPath); err != nil {
				log.Fatalf("Unable to chroot into %s: %v\n", inspectorOptions.DstPath, err)
			}
			servePath = CHROOT_SERVE_PATH
		} else {
			log.Printf("!!!WARNING!!! It is insecure to serve the image content without changing")
			log.Printf("root (--chroot). Absolute-path symlinks in the image can lead to disclose")
			log.Printf("information of the hosting system.")
		}

		log.Printf("Serving image content %s on webdav://%s%s", inspectorOptions.DstPath, inspectorOptions.Serve, CONTENT_URL_PREFIX)

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
			FileSystem: webdav.Dir(servePath),
			LockSystem: webdav.NewMemLS(),
		})

		log.Fatal(http.ListenAndServe(inspectorOptions.Serve, nil))
	}
}
