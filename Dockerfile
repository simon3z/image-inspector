FROM centos:7
MAINTAINER Federico Simoncelli <fsimonce@redhat.com>

RUN yum install -y golang git && yum clean all

WORKDIR /go/src/github.com/openshift/image-inspector
ADD .   /go/src/github.com/openshift/image-inspector
ENV GOPATH /go
ENV PATH $PATH:$GOROOT/bin:$GOPATH/bin

RUN go get github.com/openshift/image-inspector && \
    go build && \
    mv ./image-inspector /usr/bin/

ENTRYPOINT ["/usr/bin/image-inspector"]
