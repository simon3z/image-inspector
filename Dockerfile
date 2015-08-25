FROM centos:7
MAINTAINER Federico Simoncelli <fsimonce@redhat.com>

RUN yum install -y golang git && yum clean all

WORKDIR /go/src/github.com/simon3z/docker-fleece
ADD .   /go/src/github.com/simon3z/docker-fleece
ENV GOPATH /go
ENV PATH $PATH:$GOROOT/bin:$GOPATH/bin

RUN go get github.com/simon3z/docker-fleece && \
    go build && \
    mv ./docker-fleece /usr/bin/

ENTRYPOINT ["/usr/bin/docker-fleece"]
