package imageserver

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"syscall"

	"golang.org/x/net/webdav"

	docker "github.com/fsouza/go-dockerclient"
	iiapi "github.com/openshift/image-inspector/pkg/api"
)

const (
	// CHROOT_SERVE_PATH is the path to server if we are performing a chroot
	// this probably does not belong here.
	CHROOT_SERVE_PATH = "/"
)

// webdavImageServer implements ImageServer.
type webdavImageServer struct {
	opts   ImageServerOptions
	chroot bool
}

// ensures this always implements the interface or fail compilation.
var _ ImageServer = &webdavImageServer{}

// NewWebdavImageServer creates a new webdav image server.
func NewWebdavImageServer(opts ImageServerOptions, chroot bool) ImageServer {
	return &webdavImageServer{
		opts:   opts,
		chroot: chroot,
	}
}

// ServeImage Serves the image.
func (s *webdavImageServer) ServeImage(imageMetadata *docker.Image,
	meta *iiapi.InspectorMetadata,
	scanReport []byte,
	htmlScanReport []byte) error {

	servePath := s.opts.ImageServeURL
	if s.chroot {
		if err := syscall.Chroot(s.opts.ImageServeURL); err != nil {
			return fmt.Errorf("Unable to chroot into %s: %v\n", s.opts.ImageServeURL, err)
		}
		servePath = CHROOT_SERVE_PATH
	} else {
		log.Printf("!!!WARNING!!! It is insecure to serve the image content without changing")
		log.Printf("root (--chroot). Absolute-path symlinks in the image can lead to disclose")
		log.Printf("information of the hosting system.")
	}

	log.Printf("Serving image content %s on webdav://%s%s", s.opts.ImageServeURL, s.opts.ServePath, s.opts.ContentURL)

	http.HandleFunc(s.opts.HealthzURL, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok\n"))
	})

	http.HandleFunc(s.opts.APIURL, func(w http.ResponseWriter, r *http.Request) {
		body, err := json.MarshalIndent(s.opts.APIVersions, "", "  ")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Write(body)
	})

	http.HandleFunc(s.opts.MetadataURL, func(w http.ResponseWriter, r *http.Request) {
		body, err := json.MarshalIndent(meta, "", "  ")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Write(body)
	})

	http.HandleFunc(s.opts.ScanReportURL, func(w http.ResponseWriter, r *http.Request) {
		if s.opts.ScanType != "" && meta.OpenSCAP.Status == iiapi.StatusSuccess {
			w.Write(scanReport)
		} else {
			if meta.OpenSCAP.Status == iiapi.StatusError {
				http.Error(w, fmt.Sprintf("OpenSCAP Error: %s", meta.OpenSCAP.ErrorMessage),
					http.StatusInternalServerError)
			} else {
				http.Error(w, "OpenSCAP option was not chosen", http.StatusNotFound)
			}
		}
	})

	http.HandleFunc(s.opts.HTMLScanReportURL, func(w http.ResponseWriter, r *http.Request) {
		if s.opts.ScanType != "" && meta.OpenSCAP.Status == iiapi.StatusSuccess && s.opts.HTMLScanReport {
			w.Write(htmlScanReport)
		} else {
			if meta.OpenSCAP.Status == iiapi.StatusError {
				http.Error(w, fmt.Sprintf("OpenSCAP Error: %s", meta.OpenSCAP.ErrorMessage),
					http.StatusInternalServerError)
			} else {
				http.Error(w, "OpenSCAP option was not chosen", http.StatusNotFound)
			}
		}
	})

	http.Handle(s.opts.ContentURL, &webdav.Handler{
		Prefix:     s.opts.ContentURL,
		FileSystem: webdav.Dir(servePath),
		LockSystem: webdav.NewMemLS(),
	})

	return http.ListenAndServe(s.opts.ServePath, nil)
}
