#!/bin/bash

# see https://github.com/openshift/origin/blob/master/hack/lib/util/environment.sh

# This script holds library functions for setting up the shell environment for OpenShift scripts
#
# This script assumes $OS_ROOT is set before being sourced
source "${OS_ROOT}/hack/util.sh"

# os::util::environment::setup_time_vars sets up environment variables that describe durations of time
# These variables can be used to specify times for other utility functions
#
# Globals:
#  None
# Arguments:
#  None
# Returns:
#  - export TIME_MS
#  - export TIME_SEC
#  - export TIME_MIN
function os::util::environment::setup_time_vars() {
    export TIME_MS=1
    export TIME_SEC="$(( 1000  * ${TIME_MS} ))"
    export TIME_MIN="$(( 60 * ${TIME_SEC} ))"
}

# os::util::environment::setup_all_server_vars sets up all environment variables necessary to configure and start an OpenShift server
#
# Globals:
#  - OS_ROOT
#  - PATH
#  - TMPDIR
#  - LOG_DIR
#  - ARTIFACT_DIR
# Arguments:
#  - 1: the path under the root temporary directory for OpenShift where these subdirectories should be made
# Returns:
#  - export PATH
#  - export BASETMPDIR
#  - export LOG_DIR
#  - export VOLUME_DIR
#  - export ARTIFACT_DIR
function os::util::environment::setup_all_server_vars() {
    local subtempdir=$1

    os::util::environment::update_path_var
    os::util::environment::setup_tmpdir_vars "${subtempdir}"
}

# os::util::environment::update_path_var updates $PATH so that OpenShift binaries are available
#
# Globals:
#  - OS_ROOT
#  - PATH
# Arguments:
#  None
# Returns:
#  - export PATH
function os::util::environment::update_path_var() {
    export PATH="${OS_ROOT}/_output/local/bin/$(os::util::host_platform):${PATH}"
}

# os::util::environment::setup_misc_tmpdir_vars sets up temporary directory path variables
#
# Globals:
#  - TMPDIR
#  - LOG_DIR
#  - ARTIFACT_DIR
# Arguments:
#  - 1: the path under the root temporary directory for OpenShift where these subdirectories should be made
# Returns:
#  - export BASETMPDIR
#  - export LOG_DIR
#  - export VOLUME_DIR
#  - export ARTIFACT_DIR
#  - export FAKE_HOME_DIR
#  - export HOME
function os::util::environment::setup_tmpdir_vars() {
    local sub_dir=$1

    export BASETMPDIR="${TPMDIR:-/tmp}/image-inspector/${sub_dir}"
    export LOG_DIR="${LOG_DIR:-${BASETMPDIR}/logs}"
    export VOLUME_DIR="${BASETMPDIR}/volumes"
    export ARTIFACT_DIR="${ARTIFACT_DIR:-${BASETMPDIR}/artifacts}"

    # change the location of $HOME so no one does anything naughty
    export FAKE_HOME_DIR="${BASETMPDIR}/openshift.local.home"
    export HOME="${FAKE_HOME_DIR}"

    mkdir -p  "${BASETMPDIR}" "${LOG_DIR}" "${VOLUME_DIR}" "${ARTIFACT_DIR}" "${HOME}"
}
