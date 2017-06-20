#!/bin/sh

set -e

IMAGENAME=${IMAGENAME:-docker.io/openshift/image-inspector}
EXTRACTNAME=${EXTRACTNAME:-image-inspector-extract}
BINNAME=image-inspector

rm -f ${BINNAME}

echo Building ${IMAGENAME}:build

docker build --no-cache --pull -t ${IMAGENAME}:build . -f Dockerfile.build

docker create --name ${EXTRACTNAME} ${IMAGENAME}:build
docker cp ${EXTRACTNAME}:/usr/bin/${BINNAME} ${BINNAME}
docker rm -f ${EXTRACTNAME}

echo Building ${IMAGENAME}:latest

docker build --no-cache --pull -t ${IMAGENAME}:latest .
