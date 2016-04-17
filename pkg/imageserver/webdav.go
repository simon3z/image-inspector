package imageserver

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"syscall"

	"golang.org/x/net/webdav"

	docker "github.com/fsouza/go-dockerclient"

	kauthapi "k8s.io/kubernetes/pkg/apis/authorization"
	krestclient "k8s.io/kubernetes/pkg/client/restclient"
	kclient "k8s.io/kubernetes/pkg/client/unversioned"
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
func (s *webdavImageServer) ServeImage(imageMetadata *docker.Image) error {
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

	http.HandleFunc(s.opts.APIURL, s.handlerFuncAuth(func(w http.ResponseWriter, r *http.Request) {
		body, err := json.MarshalIndent(s.opts.APIVersions, "", "  ")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Write(body)
	}))

	http.HandleFunc(s.opts.MetadataURL, s.handlerFuncAuth(func(w http.ResponseWriter, r *http.Request) {
		body, err := json.MarshalIndent(imageMetadata, "", "  ")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Write(body)
	}))

	http.Handle(s.opts.ContentURL, s.newAuthenticatedHandler(&webdav.Handler{
		Prefix:     s.opts.ContentURL,
		FileSystem: webdav.Dir(servePath),
		LockSystem: webdav.NewMemLS(),
	}))

	return http.ListenAndServe(s.opts.ServePath, nil)
}

func (s *webdavImageServer) authenticate(r *http.Request) (bool, error) {
	authenticator, ok := map[AuthenticationType]func(*http.Request) (bool, error){
		AllowAll:        allowAll,
		KubernetesToken: kubernetesTokenAuth,
	}[s.opts.AuthType]
	if !ok {
		return false, fmt.Errorf("%s is not a recognize authentication method", s.opts.AuthType)
	}
	return authenticator(r)
}

func allowAll(r *http.Request) (bool, error) {
	return true, nil
}

func kubernetesTokenAuth(r *http.Request) (bool, error) {
	conf, err := krestclient.InClusterConfig()
	if err != nil {
		return false, err
	}
	conf.BearerToken = r.Header.Get("Authorization")
	kc, err := kclient.New(conf)
	if err != nil {
		return false, err
	}
	result := &kauthapi.SubjectAccessReview{}
	sar := &kauthapi.SubjectAccessReview{}
	sar.Kind = "SubjectAccessReview"
	sar.APIVersion = "v1"
	sar.Spec.ResourceAttributes.Verb = "GET"
	sar.Spec.ResourceAttributes.Resource = "images"
	err = kc.Get().Resource("subjectAccessReview").Body(sar).Do().Into(result)
	if err != nil {
		return false, err
	}
	return result.Status.Allowed, nil
}

func (s *webdavImageServer) handlerFuncAuth(f http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if allowed, err := s.authenticate(r); allowed && err == nil {
			f(w, r)
		} else {
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
			} else {
				http.Error(w, "Unauthorazied Access!", http.StatusForbidden)
			}
		}
	}
}

type authenticatedHandler struct {
	serveHttp func(http.ResponseWriter, *http.Request)
}

func (ah *authenticatedHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ah.serveHttp(w, r)
}

func (s *webdavImageServer) newAuthenticatedHandler(h http.Handler) http.Handler {
	return &authenticatedHandler{serveHttp: s.handlerFuncAuth(h.ServeHTTP)}
}
