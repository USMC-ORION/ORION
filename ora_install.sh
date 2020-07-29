#!/bin/sh

cd orion
mvn clean install -DskipTests
onos-app localhost install! target/orion-1.0-SNAPSHOT.oar
