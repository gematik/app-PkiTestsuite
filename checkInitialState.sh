#!/bin/bash

mvn verify -Dit.test=de.gematik.pki.pkits.testsuite.approval.ApprovalTestIT#checkInitialState -DfailIfNoTests=false -Dl4j.level=info
