#!/bin/sh

cd onos
echo "Starting ONOS Server..."
bazel run onos-local -- clean debug

