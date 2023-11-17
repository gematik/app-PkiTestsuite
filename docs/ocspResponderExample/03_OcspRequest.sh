#!/bin/bash

openssl ocsp -url http://127.0.0.1:8080/ocsp/1 -issuer "../../testDataTemplates/certificates/ecc/trustStore/GEM.SMCB-CA10_TEST-ONLY.pem" -serial 874437375802245 -no_cert_verify
