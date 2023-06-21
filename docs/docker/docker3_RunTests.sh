#!/bin/bash

HOSTNAME=localhost

cp ./docs/configs/inttest/pkits_docker.yml ./config/pkits.yml

sed -i "s/HOSTNAME_TO_REPLACE/${HOSTNAME}/g" ./config/pkits.yml

./startApprovalTest.sh