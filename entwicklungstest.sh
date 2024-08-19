#!/bin/bash

java -jar ./bin/pkits-sut-server-sim-exec.jar &> ./out/logs/sut.log &
java -jar ./bin/pkits-testsuite-exec.jar "$@"
