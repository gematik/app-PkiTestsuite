#!/bin/bash

openssl ocsp -url http://127.0.0.1:8080/ocsp/1 -issuer "../../testDataTemplates/certificates/rsa/trustStore/GEM.KOMP-CA40_TEST-ONLY.pem" -serial 889020133327355 -no_cert_verify
