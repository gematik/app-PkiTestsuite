#!/bin/bash

export appVersion=`mvn help:evaluate -Dexpression=project.version -q -DforceStdout`
export HOSTNAME=localhost

docker-compose --project-name pkits-services  -f docker-compose-base.yml  -f docker-compose-deployLocal.yml   down -v
docker-compose --project-name pkits-services  -f docker-compose-base.yml  -f docker-compose-deployLocal.yml   up -d
