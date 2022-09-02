<img align="right" width="200" height="37" src="docs/img/Gematik_Logo_Flag.png"/> <br />

# Release notes PKI Test Suite

## Release 0.2.1 (2022-09-02)

### changed

- remove IDP client (it will be separated from the test suite)
- disable spotless:check during test suite execution (it will be used in development only)
- repair broken images

## Release 0.2.0 (2022-09-01)

### added

- tests for TUC_PKI_006 OCSP response validation
- ./checkInitialState.sh to make a quick smoke test
- selection of test cases to be executed
- introduce use case api

### changed

- use bouncy castle provider for usage of ecc brainpool curves during tsl handshakes
- use google java code format
- raise line coverage
- update dependencies

## Release 0.1.1 (2022-06-03)

- bug fixes in build pipeline

## Release 0.1.0 (2022-06-03)

- This is the initial internal release of PKI test suite
- OCSP responder simulator with basic functionalities
- TSL provider simulator with basic functionalities
- System Under Test server (SUT) (test object simulator) with basic functionalities
- Certificate checks of TUC_PKI_018 are implemented
- TSL signer OCSP check as one part of TUC_PKI_001 is implemented
- OCSP cert hash checks as part of TUC_PKI_006 are implemented
- see [README.md](README.md) for usage instructions and further information
