**Note:** on going development has been moved to [openshift/image-inspector](https://github.com/openshift/image-inspector)

# Image Inspector

Image Inspector can extract docker images to a target directory and
(optionally) serve the content through webdav.

    $ ./image-inspector --image=fedora:22 --serve 0.0.0.0:8080
    2015/12/10 19:24:44 Image fedora:22 is available, skipping image pull
    2015/12/10 19:24:44 Extracting image fedora:22 to
                        /var/tmp/image-inspector-121627917
    2015/12/10 19:24:46 Serving image content
                        /var/tmp/image-inspector-121627917 on
                        webdav://0.0.0.0:8080/api/v1/content/

    $ cadaver http://localhost:8080/api/v1/content
    dav:/api/v1/content/> ls
    Listing collection `/api/v1/content/': succeeded.
    Coll:   boot                                4096  Dec 10 20:24
    Coll:   dev                                 4096  Dec 10 20:24
    Coll:   etc                                 4096  Dec 10 20:24
    Coll:   home                                4096  Dec 10 20:24
    Coll:   lost+found                          4096  Dec 10 20:24
    ...

# Building

To build image-inspector using godep:

    $ godep go build

# Running as a container

    $ docker run -ti --rm --privileged \
      -v /var/run/docker.sock:/var/run/docker.sock \
      openshift/image-inspector --image=fedora:20 --path=/tmp/image-content
