#!/bin/bash

if [ -n "$1" ]
  then
    PARAM_PKITS_CONFIG=$1
    pkitsConfig="-DpkitsConfig=$PARAM_PKITS_CONFIG"

  if [ ! -f "$PARAM_PKITS_CONFIG" ]; then
    echo -e "\n\nconfig file <$PARAM_PKITS_CONFIG> does not exist.\n\n\n"
    exit 1
  fi
  echo -e "\n\nprovided config file at $PARAM_PKITS_CONFIG will be used\n\n\n"
else
  DEFAULT_PKITS_CONFIG='./config/pkits.yml'
  if [ ! -f "$DEFAULT_PKITS_CONFIG" ]; then
    echo -e "\n\nconfig file <$DEFAULT_PKITS_CONFIG> (default location) does not exist.\n\n\n"
    exit 1
  fi
  echo -e "\n\ndefault config file at $DEFAULT_PKITS_CONFIG will be used\n\n\n"
fi

customFileNamePostfix=-Dlog4j2.customFileNamePostfix=_`date "+%Y%m%d_%H%M%S"`

logLevelPkiTs=-Dlog4j2.rootLogLevel=info
logLevelOcsp=-Dlog4j2.rootLogLevelOcspResponder=info
logLevelTsl=-Dlog4j2.rootLogLevelTslProvider=info

java $logLevelPkiTs $logLevelOcsp $logLevelTsl  $customFileNamePostfix  $pkitsConfig  -jar ./bin/pkits-testsuite-exec.jar

printf "...done!"
