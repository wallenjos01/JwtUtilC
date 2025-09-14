#!/bin/sh

WORK_DIR=$(pwd)

SCRIPT_DIR=$(dirname "$0")
ROOT_DIR=$(realpath ${SCRIPT_DIR}/..)
BUILD_DIR=$ROOT_DIR/build
VENV_DIR=$BUILD_DIR/.venv

BUILD_TYPE=${1:-Release}

if [ ! -d $VENV_DIR ]; then
    echo "Setting up virtual environment..."
    mkdir -p $VENV_DIR
    python3 -m venv $VENV_DIR
fi

source $VENV_DIR/bin/activate
if [ ! -f $VENV_DIR/bin/conan ]; then
    echo "Installing Conan..."
    pip install conan
    conan profile detect -e
    conan remote update conancenter --url="https://center2.conan.io"
fi

conan install ${ROOT_DIR} --build=missing -s build_type=${BUILD_TYPE}

PRESET=conan-$(echo $BUILD_TYPE | tr '[:upper:]' '[:lower:]')

cd $ROOT_DIR
cmake --preset=$PRESET

cd $WORK_DIR
