#!/bin/bash

# This script tests the high level end-to-end functionality demonstrated
# as part of the examples/sample-app

set -o errexit
set -o nounset
set -o pipefail

STARTTIME=$(date +%s)
OS_ROOT=$(dirname "${BASH_SOURCE}")/..

source "${OS_ROOT}/hack/util.sh"
os::log::install_errexit

go build -o _output/local/bin/image-inspector cmd/image-inspector.go
export PATH=${OS_ROOT}/_output/local/bin:$PATH
$OS_ROOT/test/end-to-end/e2e.sh
