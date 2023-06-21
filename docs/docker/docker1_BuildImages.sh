#!/bin/bash

mvn clean \
  -Dskip.dockerbuild=false \
  -Dcommit_hash=`git log --pretty=format:'%H' -n 1` \
  install \
  -am -pl pkits-ocsp-responder,pkits-tsl-provider \
  "$@"
