package inspector

import (
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"math"
	"math/big"
	"os"
	"path"
	"strings"

	"archive/tar"
	"crypto/rand"

	docker "github.com/fsouza/go-dockerclient"

	iicmd "github.com/simon3z/image-inspector/pkg/cmd"
	apiserver "github.com/simon3z/image-inspector/pkg/imageserver"
)

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

// ImageInspector is the interface for all image inspectors.
type ImageInspector interface {
	// Inspect inspects and serves the image based on the ImageInspectorOptions.
	Inspect() error
}

// defaultImageInspector is the default implementation of ImageInspector.
type defaultImageInspector struct {
	opts iicmd.ImageInspectorOptions
	// an optional image server that will server content for inspection.
	imageServer apiserver.ImageServer
}

// NewDefaultImageInspector provides a new default inspector.
func NewDefaultImageInspector(opts iicmd.ImageInspectorOptions) ImageInspector {
	inspector := &defaultImageInspector{
		opts: opts,
	}

	// if serving then set up an image server
	if len(opts.Serve) > 0 {
		imageServerOpts := apiserver.ImageServerOptions{
			ServePath:     opts.Serve,
			HealthzURL:    HEALTHZ_URL_PATH,
			APIURL:        API_URL_PREFIX,
			APIVersions:   apiserver.APIVersions{Versions: []string{VERSION_TAG}},
			MetadataURL:   METADATA_URL_PATH,
			ContentURL:    CONTENT_URL_PREFIX,
			ImageServeURL: opts.DstPath,
			AuthType:      apiserver.AuthenticationType(opts.ServerAuthType),
		}
		inspector.imageServer = apiserver.NewWebdavImageServer(imageServerOpts, opts.Chroot)
	}
	return inspector
}

// Inspect inspects and serves the image based on the ImageInspectorOptions.
func (i *defaultImageInspector) Inspect() error {
	client, err := docker.NewClient(i.opts.URI)
	if err != nil {
		return fmt.Errorf("Unable to connect to docker daemon: %v\n", err)
	}

	if _, err := client.InspectImage(i.opts.Image); err != nil {
		log.Printf("Pulling image %s", i.opts.Image)
		imagePullOption := docker.PullImageOptions{Repository: i.opts.Image}

		var imagePullAuths *docker.AuthConfigurations
		var authCfgErr error
		if imagePullAuths, authCfgErr = getAuthConfigs(i.opts.DockerCfg, i.opts.Username, i.opts.PasswordFile); authCfgErr != nil {
			return authCfgErr
		}

		// Try all the possible auth's from the config file
		var authErr error
		for _, auth := range imagePullAuths.Configs {
			if authErr = client.PullImage(imagePullOption, auth); authErr == nil {
				break
			}
		}
		if authErr != nil {
			return fmt.Errorf("Unable to pull docker image: %v\n", authErr)
		}
	} else {
		log.Printf("Image %s is available, skipping image pull", i.opts.Image)
	}

	randomName, err := generateRandomName()
	if err != nil {
		return err
	}

	container, err := client.CreateContainer(docker.CreateContainerOptions{
		Name: randomName,
		Config: &docker.Config{
			Image: i.opts.Image,
			// For security purpose we don't define any entrypoint and command
			Entrypoint: []string{""},
			Cmd:        []string{""},
		},
	})
	if err != nil {
		return fmt.Errorf("Unable to create docker container: %v\n", err)
	}

	containerMetadata, err := client.InspectContainer(container.ID)
	if err != nil {
		return fmt.Errorf("Unable to get docker container information: %v\n", err)
	}

	imageMetadata, err := client.InspectImage(containerMetadata.Image)
	if err != nil {
		return fmt.Errorf("Unable to get docker image information: %v\n", err)
	}

	if len(i.opts.DstPath) > 0 {
		err = os.Mkdir(i.opts.DstPath, 0755)
		if err != nil {
			if !os.IsExist(err) {
				return fmt.Errorf("Unable to create destination path: %v\n", err)
			}
		}
	} else {
		// forcing to use /var/tmp because often it's not an in-memory tmpfs
		i.opts.DstPath, err = ioutil.TempDir("/var/tmp", "image-inspector-")
		if err != nil {
			return fmt.Errorf("Unable to create temporary path: %v\n", err)
		}
	}

	reader, writer := io.Pipe()
	go handleTarStream(reader, i.opts.DstPath)

	log.Printf("Extracting image %s to %s", i.opts.Image, i.opts.DstPath)
	err = client.CopyFromContainer(docker.CopyFromContainerOptions{
		Container:    container.ID,
		OutputStream: writer,
		Resource:     "/",
	})
	if err != nil {
		return fmt.Errorf("Unable to extract container: %v\n", err)
	}

	_ = client.RemoveContainer(docker.RemoveContainerOptions{
		ID: container.ID,
	})

	if i.imageServer != nil {
		return i.imageServer.ServeImage(imageMetadata)
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

func generateRandomName() (string, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(math.MaxInt64))
	if err != nil {
		return "", fmt.Errorf("Unable to generate random container name: %v\n", err)
	}
	return fmt.Sprintf("image-inspector-%016x", n), nil
}

func getAuthConfigs(dockercfg, username, password_file string) (*docker.AuthConfigurations, error) {
	imagePullAuths := &docker.AuthConfigurations{
		map[string]docker.AuthConfiguration{"": {}}}
	if dockercfg != "" {
		reader, err := os.Open(dockercfg)
		if err != nil {
			return nil, fmt.Errorf("Unable to open docker config file: %v\n", err)
		}
		if imagePullAuths, err = docker.NewAuthConfigurations(reader); err != nil {
			return nil, fmt.Errorf("Unable to parse docker config file: %v\n", err)
		}
		if len(imagePullAuths.Configs) == 0 {
			return nil, fmt.Errorf("No auths were found in the given dockercfg file\n")
		}
	}
	if username != "" {
		token, err := ioutil.ReadFile(password_file)
		if err != nil {
			return nil, fmt.Errorf("Unable to read password file: %v\n", err)
		}
		imagePullAuths = &docker.AuthConfigurations{
			map[string]docker.AuthConfiguration{"": {Username: username, Password: string(token)}}}
	}

	return imagePullAuths, nil
}
