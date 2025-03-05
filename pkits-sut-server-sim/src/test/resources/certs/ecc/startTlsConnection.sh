#!/bin/bash

# script works independent of where you invoke it from
SCRIPT_PATH=$( cd "$(dirname "${BASH_SOURCE[0]}")" ; pwd -P )
cd "$SCRIPT_PATH"


host=localhost:8443
#resource=/
resource=/ssl-test

(echo -ne "GET $resource HTTP/1.1\r\nHost: localhost\r\n\r\n") | openssl s_client -no_tls1_3 -cipher ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-GCM-SHA256 -curves brainpoolP256r1 -connect $host -cert authZahnarztpraxisDrFolEpi.pem -key authZahnarztpraxisDrFolEpi.key.pem -verify_return_error -partial_chain -CAfile chain_ecc.pem
