<img align="right" width="200" height="37" src="docs/img/Gematik_Logo_Flag.png"/> <br />

# ![Logo](./docs/img/test.png) PKI Test Suite

<div>Icon made by <a href="https://www.freepik.com" title="Freepik">Freepik</a> from 
<a href="https://www.flaticon.com/" title="Flaticon">www.flaticon.com</a></div>

This test suite is used to verify a telematic infrastructure (TI) product server of the German
health care system against gematik gemSpec_PKI specifications available
at [gematik Fachportal](https://fachportal.gematik.de/). Especially TUC_PKI_001 (TSL validation),
TUC_PKI_018 (certificate validation) and TUC_PKI_006 (OCSP response validation). It is used for
approval tests of every PKI related aspect. It is a re-development of our test suite from 2016. The
development is still ongoing [see Todo section](./README.md#todo)

## Versioning

Versions below 1.0.0 are considered incomplete.

## Remark

Cryptographic private keys used in this project are solely used in test resources for the purpose of
(unit) tests. We are fully aware of the content and meaning of the test data. We never publish
productive data.

## Technical Functionality

The test suite consists of four parts necessary for validating a PKI test object. These are
implemented as maven modules:

### 1. PKI Test Suite

This is the tests suite itself. It is used to start all following modules, configure them and read
the results. It has a main
class [ApprovalTestsIT](pkits-testsuite/src/test/java/de/gematik/pki/pkits/testsuite/approval/ApprovalTestIT.java)
that inherits all PKI tests and is executed via maven-failsafe-plugin. The test suite calls a use
case (see [Use Case Modules](./README.md#4-use-case-modules)) and expects it to either pass or fail,
depending on the test data used. If the expectation is fulfilled, the test case is passed.

### 2. TSL Provider

The TSL provider is started as an own process. It is configured and started during the PKI tests by
the PKI test suite module to deliver a TSL to the test object. It is implemented as a spring boot
tomcat web server.

### 3. OCSP Responder

The OCSP responder is started as an own process. It is started and configured during the PKI tests
by the PKI test suite module to answer OCSP requests sent by the test object. This configuration is
done over a REST interface and absolutely transparent to the user. Depending on the tests executed
it is configured to deliver unsigned OCSP responses, wrong cert hashes and so on. It is implemented
as a spring boot tomcat web server.

### 4. Use Case Modules

At the moment there are three ways of communicating with a test object. In all scenarios the test
object has to be a server. This means, the PKI test suite acts like a client during PKI tests.

#### TLS Client

The TLS client module is started as an own process. It establishes a TLS handshake to a test object
with a given certificate (see [test data section](./README.md#test-data)) and returns exit code "0"
if the handshake was established or "1" if it was not.

#### IDP Client

The IDP client module is started as an own process. It queries an IDP server for a jwt access token
using a given eGK certificate (see [test data section](./README.md#test-data)) and returns "0" if
the token can be obtained correctly or "1" if it cannot. This module is still in development.

#### Script

A script (shell, batch or other executable program) is started as an own process. A script
can be written from every PKI test suite user to communicate with a test object. The test suite
passes two parameters as command line arguments to any call: `pathToCertificate`
and `certificatePassword` in this order.
Be sure to return exit code "0" if the communication was successful and "1" if it was not. Be
careful about the exit code. Thr script solely should only return "0" if the use case was
successful, **not if the script could be executed successful!**

## Configuration

All configuration is done in one file: `./config/pkits.yml`. You can find examples
in [/docs/config/inttest/](./docs/configs/inttest/). The most important parameters
are how to reach the test object and where to find the test data as well as where the test object
can reach the tsl and OCSP simulators provided by this test suite. Paths are relative to the
directory `./pkits-testsuite` or can be absolute. As this is a YAML file remember to strictly follow
the syntax.

### Test Data

We deliver some test data in the directory `./testDataTemplates`. These test data are for our own
integration tests and can be used for approval tests as well. The test data form an own PKI, hence
it is not easy to create them by yourself. In later releases it is planned to generate test data on
the fly. If you use your own test data make sure that issuing certificates are added in the
[tsl template](./testDataTemplates/tsl/tslTemplateEcc.xml) as well.

#### Certificates

The two configuration parameters `client.keystorePathValidCerts`
and `client.keystorePathInvalidCerts` point to the directories where to find valid and invalid sets
of *.p12 certificate containers. The certificates are used to execute a Use Case and trigger the
TUC_PKI_018 checks inside a test object.

#### TSL's

At the moment there is only one TSL template used in the test suite. It contains necessary CA and
signer certificates for the certificate and OCSP checks. Dates and URI values, as well as the
signature are set during test execution depending on the parameters set in the configuration file.
The template is based on the
official [Arvato TU ECC TSL](https://download-test.tsl.ti-dienste.de/ECC/ECC-RSA_TSL-test.xml)

### Initial TSL and Trust Anchor

For the configuration of the test object it is necessary to initialize it with a trust space
compatible to the test suite. For this, a convenient script ist provided by the test suite:
By executing `initialTslAndVa.sh` an initial TSL and the corresponding trust anchor are written to
the `./out` directory for import into the test object.

## Test Execution

Tests are executed via the script `./startApprovalTest.sh`. It will compile all modules and run the
main class
[ApprovalTestsIT](pkits-testsuite/src/test/java/de/gematik/pki/pkits/testsuite/approval/ApprovalTestIT.java)
via maven-failsafe-plugin. Furthermore, the [OCSP responder](./README.md#3-ocsp-responder)
and [TSLl provider](./README.md#4-use-case-modules) are started at the configured sockets. Logs are
written to the `./out/logs` directory. Afterwards a test report is generated in
the `./out/testreport` directory.

### Smoke Test

In oder to make a quick check if everything is set up correctly, we implemented a script that runs
an initial test: `./checkInitialState.sh`. Within a TSL download is checked and afterwards a use
case is triggered with a valid certificate. OCSP requests are expected and answered correctly.

### Selecting Specific Tests

Besides executing all tests, it is possible to select specific tests for execution. This is done
via the file `allTest.txt`. Tests marked with a `+` will be executed when `./startApprovalTests.sh`
is used the next time. The first line of the file (package name of the ApprovalTestsIT class)
selects all tests in the class.

### Requirements

In order to run the test suite, you need a build environment consisting of `Java 17`
and `Maven 3.6.3`. The test suite is developed with OpenJdk 17.

## Todo

- add tests of TUC_PKI_001
- add PKI client tests
- finish IDP client to enable PKI tests of an IDP server
- add generation of test data on the fly
