<img align="right" width="200" height="37" src="docs/img/Gematik_Logo_Flag.png"/> <br />

# Release notes PKI Test Suite

## Release 2.5.1

- update dependencies
- add egk certs for Idp Server which checks eGK certs

## Release 2.4.2

- update dependencies

## Release 2.4.1

- FIX test case verifyExpiredTslInSystem: tolerate missing tsl download (What is crucial is that the
  test object recognizes the TSL expiration and invalidates the trust store)

## Release 2.4.0

- change the order of the elements in the subjectDN of the ocsp responder id
- allow brainpool curves in RSA during ECDH according to GS-A_4384-01
- update dependencies

## Release 2.3.1

- update TSL template to latest revision
- raise verbosity output of tls connection phase
- raise stability
- update dependencies

## Release 2.3.0

- extend validity of default TSL Signer certificate
- add example scripts for independent usage of the OCSP
  responder [ocspResponderExample](docs%2FocspResponderExample)
- remove tests (certificates) of wrong admissions because they are too academical
- change mechanism of zip-package creation by using a dedicated maven module
- update dependencies
- code optimizations

## Release 2.2.0

- add tests for admission and profession oid's for test object types that have to evaluate roles
- BUGFIX: prevent checkInitialState from passing when performInitialState is not true
- BUGFIX: initialTslAndTa.sh from failing
- change shell scripts to return correct error code
- update dependencies

## Release 2.1.0

- API CHANGE: introduce test object type. Instead of choosing the right certificate path for a test
  object, it is now possible to use a parameter (`testObjectType`) instead. (one of:
  IntermediaerServer, KimFachdienst, VsdmFachdienst, VpnKonzentrator, VpnRegServer, IdpFachdienst) (
  see section [configuration](./README.md#configuration) in readme)
- change behaviour of test case `verifyExpiredTslInSystem()` to allow a test object to invalidate
  the trust store immediately after expiration of the TSL
- NEW test case: `verifyUseCaseRsaCertValid()` which uses a RSA certificate for the use case
- NEW test cases: check hash algorithm in OCSP context
- BUGFIX: correct extension oid in TSL services
- BUGFIX: prevent possibility to write unsigned TSL to out directory
- change communication between test suite and simulators to json (instead of java serialization)
- remove config parameter: `tslSettings.initialStateTslImport`
- remove unused test data for checks of keyUsage and extendedKeyUsage; we do not check for these
  errors
- correct and update AFO annotations
- establish swagger api documentation in server simulators at: `http://server:port/api-docs`
- javadoc is not generated anymore
- change OCSP responder to actually calculate issuerCertHash and issuerKeyHash instead of mirroring
  the request
- optimize execution time of parameterized tests by skipping initial state for the non-first test
  cases
- add gematik security policy
- refactor code for better readability and consolidate certificate constants
- increase code coverage
- update dependencies

## Release 2.0.0 - Beryllium

- API CHANGE: rename some test cases, so old and new [allTests.txt](./allTests.txt) are incompatible
- API CHANGE: restructure pkits.yml so old config files are incompatible
  (see: [all parameters](./docs/all_pkits_parameters.yml) for more info)
- BUGFIX: repair broken test data certificates
- BUGFIX: do not execute remaining tests if a trust anchor test case failed
- BUGFIX: change ocsp request handling in verifyOcspResponseTimeoutAndDelay
- NEW test case: verifyOcspRequestStructure
- NEW test case: verifyUseCaseCertsNotInTsl
- NEW test case: verify critical extensions in certificates
- NEW test case: verifyExpiredTslInSystem. ATTENTION: this test case is executed at the end. The
  test object has to be reinitialized with a new trust space afterward, because its trust space
  is not valid anymore.
- introduce allFailed.txt to execute all failed tests quick & easy (
  see [readme](./README.md#selecting-specific-tests))
- prevent startup of PcapManager, OCSP and TSL simulators during initalTslandTa execution
- restructure the order of topics in the test report
- OCPS Responder and TSL Provider are started only once for each run
- update docker files for use with the latest docker version
- add possibility to change log level over *.sh scripts
- stabilise some test cases with rare race conditions (i.e., verifyUseBackupTslDownload,
  verifyRetryFailingTslDownload, verifyIrregularDifferencesBetweenCurrentAndNewTsls)
- increase code coverage
- restructure code for better readability
- update dependencies

## Release 1.1.3

- BUGFIX: in mechanism of test selection in allTests.txt
- do not execute checkInitialState more than once
- remove example yaml from config dir, this file should not be used in own test and lead to
  confusion
- generate test data (TSLs) on-fly (instead of reading manually prepared TSL XML templates)
- add some more test cases for deeper TSL testing
- add helper scripts and documentation for running OCSP- and TSL simulator in docker containers
- add possibility to execute scripts on remote servers via ssh
- update dependencies
- refactoring and optimizations

## Releases before 1.1.3

- internal releases

## Release 1.0.6

- upload binaries

## Releases before 1.0.6

- internal releases

## Release 1.0.1

- migrate from maven-based execution of approval tests to binary (jar) based
- enable building docker images for OCSP Responder and TSL Provider
- add verification of expected sequence number in OCSP responses

## Release 1.0.0 - Aluminium

- internal release

## Release 0.4.1

- add test cases checking number of retries for primary and backend endpoints for TSL download
- add test cases in the context of Trust Anchor Change verification—the tests are set to run as
  the last
- add test cases in the context of TSL signer certificate verification
- add test cases in the context of TSL approval verification
- force trust anchor change tests to run as last
- add documentation of all AFOs and corresponding test cases
  files: [AFOs description](./docs/afoCoverage_afoDescriptions.txt),
  [AFOs to tests mapping](./docs/afoCoverage_afoToTests.txt),
  [tests to AFOs mapping](./docs/afoCoverage_testToAfos.txt)
- introduce `externalStartup` for the case when OcspResponder and TslProvider are started
  externally (not by the test
  suite)
- integrate logs and configuration into PDF report

## Release 0.3.1

- add kim client module certificates
- update documentation

## Release 0.3.0

- add test cases in the context of tsl signer certificate ocsp status verification
- separate test cases in own classes by context (ocsp tests, tsl tests, tsl signer tests,
  certificate tests)
- add network sniffing to pcap files
- add documentation of all testsuite parameters in one
  file: [all parameters](./docs/all_pkits_parameters.yml)
- annotate test cases with corresponding AFOs
- code optimizations

## Release 0.2.1

- disable spotless:check during test suite execution (it will be used in development only)
- repair broken images
- IDP client (it will be separated from the test suite)

## Release 0.2.0

- tests for TUC_PKI_006 OCSP response validation
- ./checkInitialState.sh to make a quick smoke test
- selection of test cases to be executed
- introduce use case api
- use bouncy castle provider for usage of ecc brainpool curves during tsl handshakes
- use google java code format
- raise line coverage
- update dependencies

## Release 0.1.1

- bug fixes in a build pipeline

## Release 0.1.0

- This is the initial internal release of PKI test suite
- OCSP responder simulator with basic functionalities
- TSL provider simulator with basic functionalities
- System Under Test server (SUT) (test object simulator) with basic functionalities
- Certificate checks of TUC_PKI_018 are implemented
- TSL signer OCSP check as one part of TUC_PKI_001 is implemented
- OCSP cert hash checks as part of TUC_PKI_006 are implemented
- see [README.md](README.md) for usage instructions and further information
