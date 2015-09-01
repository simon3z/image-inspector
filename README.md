# Building image-inspector

To build image-inspector using godep:

    $ godep go build

# Running image-inspector in a container

    $ docker run -ti --rm --privileged \
      -v /var/run/docker.sock:/var/run/docker.sock \
      fsimonce/image-inspector --image=fedora:20 --path=/tmp/image-content
