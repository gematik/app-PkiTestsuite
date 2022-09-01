#!/bin/bash

mvn verify -Dit.test=de.gematik.pki.pkits.testsuite.utils.InitialTestDataTest#buildInitialTslAndVa -DfailIfNoTests=false
