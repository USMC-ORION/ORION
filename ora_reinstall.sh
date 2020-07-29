#!/bin/sh

cd orion
mvn clean install -DskipTests
onos-app localhost reinstall! target/orion-1.0-SNAPSHOT.oar
