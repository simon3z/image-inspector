#!/bin/bash

# This script tests the high level end-to-end functionality

set -o errexit
set -o nounset
set -o pipefail

OS_ROOT=$(dirname "${BASH_SOURCE}")/../..
source "${OS_ROOT}/hack/util.sh"
source "${OS_ROOT}/hack/cmd_util.sh"
os::log::install_errexit

source "${OS_ROOT}/hack/lib/util/environment.sh"
os::util::environment::setup_time_vars

# test args
os::cmd::expect_failure_and_text "image-inspector --help" "Usage of"
os::cmd::expect_failure_and_text "image-inspector" "Docker image to inspect must be specified"
os::cmd::expect_failure_and_text "image-inspector --image=fedora:22 --dockercfg=badfile" "badfile does not exist"
os::cmd::expect_failure_and_text "image-inspector --image=fedora:22 --dockercfg=badfile --username=foo" "Only specify dockercfg file or username/password pair for authentication"
os::cmd::expect_failure_and_text "image-inspector --image=fedora:22 --password-file=foo" "foo does not exist"
os::cmd::expect_failure_and_text "image-inspector --image=fedora:22 --scan-type=foo" "foo is not one of the available scan-type"


# test extraction
os::cmd::expect_success_and_text "image-inspector --image=fedora:22 2>&1" "Extracting image fedora:22"

# TODO
# test serving
# test scanning valid and invalid params

