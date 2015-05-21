# Building docker-fleece

To build docker-fleece using godep:

    $ godep go build

# Running docker-fleece in a container

    $ docker run -ti --rm --privileged \
      -v /var/run/docker.sock:/var/run/docker.sock \
      -v /tmp/docker-fleece:/tmp/docker-fleece \
      fsimonce/docker-fleece --image=fedora:20 --path=/tmp/docker-fleece
