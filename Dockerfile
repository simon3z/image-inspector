FROM centos:7
MAINTAINER Federico Simoncelli <fsimonce@redhat.com>

ADD ["docker-fleece", "/usr/bin/docker-fleece"]
ENTRYPOINT ["/usr/bin/docker-fleece"]
