#!/bin/bash

if [ -n "$1" ]
  then
    pkitsConfig="-DpkitsConfig=$1"
    echo "$pkitsConfig"
fi

customFileNamePostfix=-Dlog4j2.customFileNamePostfix=_`date "+%Y%m%d_%H%M%S"`

java  $customFileNamePostfix  $pkitsConfig  -jar ./bin/pkits-testsuite.jar

printf "...done!"
