#!/bin/bash

# script works independent of where you invoke it from
SCRIPT_PATH=$( cd "$(dirname "${BASH_SOURCE[0]}")" ; pwd -P )
cd "$SCRIPT_PATH"

host=localhost:8443
#resource=/
resource=/

(echo -ne "GET $resource HTTP/1.1\r\nHost: localhost\r\n\r\n") | openssl s_client -no_tls1_3 -cipher DHE-RSA-AES256-SHA:DHE-RSA-AES128-SHA -connect $host -cert authKrankenhausJungbrunnen.pem -key authKrankenhausJungbrunnen.key.pem -verify_return_error -partial_chain -CAfile KOMP-CA4.pem

# -CAFile:  accept Server Certs from this CA(s) just relevant for OpenSSL

# negativtest: -cipher DHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256
# positivtest: -cipher DHE-RSA-AES256-SHA:DHE-RSA-AES128-SHA

