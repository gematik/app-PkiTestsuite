#!/bin/bash

if [ -n "$1" ]
  then
    pkitsConfig="-DpkitsConfig=$1"
    echo "$pkitsConfig"
fi

java $pkitsConfig -cp ./bin/pkits-testsuite.jar de.gematik.pki.pkits.testsuite.approval.GeneratePdf

printf "...done!"
