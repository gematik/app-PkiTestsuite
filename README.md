<img align="right" width="200" height="37" src="docs/img/Gematik_Logo_Flag.png"/> <br />

# PKI Test Suite

---
<img align="left" height="150" src="docs/img/PKI_Testsuite_Blau_gematik.svg" />

This test suite is used to verify a telematic infrastructure (TI) product server of the German
health care system against gematik gemSpec_PKI specifications available
at [gematik Fachportal](https://fachportal.gematik.de/). Especially TUC_PKI_001 (TSL validation),
TUC_PKI_018 (certificate validation) and TUC_PKI_006 (OCSP response validation). It is used for
approval tests of every PKI related aspect. It is a re-development of our test suite from 2016.

Products tested by this test suite are: Intermediär, VSDM Fachdienst, VPN Zugangsdienst:
Registrierungsdienst and Konzentrator, IDP Fachdienst, KIM Fachdienst. More are coming.

---

## tl;dr

```bash 
# Download release zip file from https://github.com/gematik/app-PkiTestsuite/releases and extract it
cp <UserDefinedConfigfile>.yml ./config/pkits.yml # examples: /docs/config/inttest/
./initialTslAndTa.sh # generates trust anchor and TSL in ./out for import in test object
# The test object has to be started and accessible from now on.
./checkInitialState.sh # acquires TSL sequence number from the test object by analysing a tsl download request and applying a use case
./startApprovalTest.sh # chose tests that shall be executed from allTests.txt
# Test artefacts (i.e. logs and report) can be found in ./out directory.
```

## Technical Functionality

The test suite consists of four parts necessary for validating a PKI test object. These are
implemented as maven modules and can be used independently or in conjunction with the test suite.

### Requirements

To execute the test suite you need at least Java 17. The test suite ist build and testet
with [Eclipse Adoptium Temurin JDK 17](https://github.com/adoptium/temurin17-binaries)

For capturing network traffic via the integrated pcap interface Libpcap for Unix or Npcap for
Windows (Install Npcap in "Winpcap Compatible Mode") are required. Under linux you have to allow the
java binary to access the interface:

```bash
sudo setcap cap_net_raw,cap_net_admin=eip $PATH_TO_YOUR_JDK/bin/java
```

### 1. PKI Test Suite

This is the test suite itself. It is used to start all following modules, configure them and read
the results. It has
a [package](pkits-testsuite/src/main/java/de/gematik/pki/pkits/testsuite/approval/) with classes to
all approval tests. The test suite calls a use case
(see [Use Case Modules](./README.md#4-use-case-modules)) and expects it to either pass or fail,
depending on the test data used. If the expectation is fulfilled, the test case is passed.

The test suite has a couple of convenience options:

```bash
java -jar ./bin/pkits-testsuite-exec.jar --help
```

```text
Usage: <main class> [-h] [-np] [-faf=<failedTestCases>] [-p=NUMBER]
                    [-tf=<testCasesFile>] [-tn=<testCasesNames>]
      -faf, --failed-and-aborted-file=<failedTestCases>
                             Save all failed or aborted tests to this file. The
                               file can be used as parameter for theCLI option
                               --tests-file.
                               Default: ./allFailedOrAborted.txt
  -h, --help                 Display this help message.
      -np, --no-pdf-report   Do not generate report as PDF.
  -p, --percent=NUMBER       Execute only proportion of randomly selected tests
                               from all tests that were passed via --tests-file
                               or --tests-names). It is a number from 1 to 100.
                               At least 1 test from passed will be selected.
                               Default: 100
      -tf, --tests-file=<testCasesFile>
                             The file with tests to run.
                               Default: ./allTests.txt
      -tn, --tests-names=<testCasesNames>
                             Comma separated list of names to run, for example:
                               "verifyUseCaseCertsValid, TslApprovalTestsIT,
                               TslSignerApprovalTestsIT#checkInitialState".
```

### 2. TSL Provider

The TSL provider is a service that delivers TSLs to the test object.
The behavior of this service, such as the content of a TSL offered to the test object, is
configured automatically during the test execution over a REST interface.
The TSL provider is implemented as a spring boot tomcat web server and runs as its own process.

The socket that is runs on is configured as followed:

```yaml
tslProvider:
  ipAddressOrFqdn: "127.0.0.1"
  port: 8084
```

This configuration is also written to every tsl as the download points in `PointersToOtherTSL`. For
this reason it is crucial to configure it correctly before generating the initial TSL for the test
object (see [Initial TSL and Trust Anchor](./README.md#initial-tsl-and-trust-anchor)).

The TSL provider is started automatically at the configured socket, but in can be started
independently. To do so, one has to set `appPath` to `"externalStartup"` in the `pkits.yml`. Address
and port can be passed to the jar via `--server.port=[port]`
and `--server.address=[ipAddressOrFqdn]`. This way it is possible to run the TSL provider in a
different environment as the test suite.

The TSL provider has an open-api interface for documentation at `<socket>/api-docs`.

### 3. OCSP Responder

The OCSP responder is a service to generate responses to OCSP requests sent by the test object.
The behavior of this service is configured over a REST interface and transparent to the user.
Depending on the tests, the test suite configures it to deliver unsigned OCSP responses, wrong cert
hashes and so on.
Similar to the TSL provider, it is implemented as a spring boot tomcat web server and runs as its
own process.

The socket that is runs on is configured as followed:

```yaml
ocspResponder:
  ipAddressOrFqdn: "127.0.0.1"
  port: 8083
```

This configuration is also written to every tsl as the service supply point of each trust service.
For this reason it is crucial to configure it correctly before generating the initial TSL for the
test object (see [Initial TSL and Trust Anchor](./README.md#initial-tsl-and-trust-anchor)).

The OCSP responder is started automatically at the configured socket, but in can be started
independently. To do so, one has to set `appPath` to `"externalStartup"` in the `pkits.yml`. Address
and port can be passed to the jar via `--server.port=[port]`
and `--server.address=[ipAddressOrFqdn]`. This way it is possible to run the OCSP responder in a
different environment as the test suite.

Example scripts on how to run the OCSP responder independently for other tasks can be found in the
documentation directory: [ocspResponderExample](docs%2FocspResponderExample) or via the open-api
interface: `<socket>/api-docs`.

### 4. Use Case Modules

At the moment, there are two ways of communicating with a test object. In all scenarios, the test
object has to be a server. This means the PKI test suite acts like a client during PKI tests.

#### TLS Client

For test objects that are more or less a TLS Server, a TSL client implementation is bundled with the
test suite. It establishes a TLS handshake to a test object with a given certificate
(see [configuration](./README.md#configuration)).
Corresponding to AFOs: `GS-A_4385-01` and `A_17127-01` the TLS handshake will follow the
specifications from gemSpec_Krypt with the following parameters:

* TLS Version: 1.2
* cipher suites used: TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 or
  TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
* for the test of RSA functionality, we use the following cipher suites:
  TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 and TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
* for ECDHE either NIST P-256 or P-384 is used

#### Script

A script (shell, batch or other executable program) is started as an own process. A script
can be written from every PKI test suite user to communicate with a test object. The test suite
passes two parameters as command line arguments to any call: `pathToCertificate`
and `certificatePassword` in this order.
Be sure to return exit code "0" if the communication was successful and "1" if it was not. Be
careful about the exit code. Thr script solely should only return "0" if the use case was
successful, **not if the script could be executed successful!**

##### Script over SSH

It is possible to execute a script remotely over ssh. See `sshConfig` section in the configuration
file. You have to configure the authentication (password or certificate), files that have to be
copied to the remote location and back. As wells as the IP and port of the remote machine.

## Configuration

The configuration is done in one file: [/config/pkits.yml](./config/pkits.yml). You can find
examples in [/docs/config/inttest/](./docs/configs/inttest/). The most important parameters are:

* What is the type of the test object (e.g., KimFachdienst, IntermediaerServer, etc.)?
* How to reach the test object (i.e., ipAddress and port)?

Example:

```yaml
testObject:
  name: "Server 0815"
  testObjectType: "IntermediaerServer"
  ipAddressOrFqdn: "127.0.0.1"
  port: 8443
```

Furthermore, the test object must be able to reach the TSL- and OCSP-simulators provided by this
test suite.

Paths in the `pkits.yml` are relative to the base directory. Absolute paths can be used as well.
All available parameters including a short description can be found
in [all_pkits_parameters.yml](./docs/all_pkits_parameters.yml). As this is a YAML file remember to
strictly follow the syntax.

```text 
Remember: A change of parameters that will change the TSL (i.e. OCSP responder address and port or 
TSL provider address an port) require a new generation of the initial TSL and import to the test 
object.
``` 

### Test Data

We deliver some test data in the directory `./testDataTemplates`. Currently, these test data support
tests for the following TI products:

| Test object             | testObjectType in pkits.yml | Test data directory         |
|-------------------------|-----------------------------|-----------------------------|
| KIM Fachdienst          | KimFachdienst               | kimClientModul              |
| VPN-ZugD Konzentrator   | VpnKonzentrator             | netzkonnektorClient         |
| VPN-ZugD RegServer      | VpnRegServer                | fachmodulClient             |
| VSDM Fachdienst         | VsdmFachdienst              | intermediaerClient          |
| VSDM Intermediär Server | IntermediaerServer          | fachmodulClientIntermediaer |
| Zentraler/SmartCard IDP | IdpFachdienst               | fachmodulClient             |

These test data are for our own integration tests and can be used for approval tests as well.
The test data form an own PKI, hence it is not easy to create them by yourself. If you use your own
test data, make sure that issuing certificates are added in
the [tsl template](./testDataTemplates/tsl/ECC-RSA_TSL-test.xml) as well.

### Initial TSL and Trust Anchor

For the configuration of the test object, it is necessary to initialize it with a trust space
compatible with the test suite.
For this, a convenient script is provided by the test suite:
By executing `./initialTslAndTa.sh` an initial TSL and the corresponding trust anchor are written to
the `./out` directory for manual import into the test object.

Before generating this TSL it is crucial to configure the sockets for
the [TSL provider](./README.md#2-tsl-provider) and [OCSP responder](./README.md#3-ocsp-responder)
correctly.

This TSL contains the TU trust store as well; this means that the test object can be used during the
pki tests by other services as well.

## Test Execution

The test suite expects a test object that is running and accessible over the configured IP address
and port (see [Configuration](./README.md#configuration)). Tests are executed via the
script `./startApprovalTest.sh`.
Furthermore, the [OCSP responder](./README.md#3-ocsp-responder)
and [TSL provider](./README.md#2-tsl-provider) communicate at the configured sockets (if they are
not deactivated). Logs are written to the `./out/logs` directory. Afterward a test report is
generated in the `./out/testreport` directory.

### Smoke Test

In order to make a quick check if everything is set up correctly, the test object can be reach by
the
test suite, and to initialize the test suite with the TSL sequence number set in the test object; we
implemented a script that runs an initial test: `./checkInitialState.sh`. Within a TSL download by
the test object is expected, and afterward, a use case is triggered with a valid certificate. OCSP
requests are expected and answered correctly as well. Therefore, a configured test object has to be
up and running and accessible by the testsuite and its components.

### Selecting Specific Tests

Besides executing all tests, it is possible to select or exclude specific tests for execution.
This is done via the file `allTests.txt`.
The file lists test classes `CertificateApprovalTests`, `OcspApprovalTests`,
`TslApprovalTests`, `TslITSignerApprovalTests`, `TslTaApprovalTests` and all tests defined in
the test classes.
Test classes as well as separate tests can be marked with `+` or `-`.
Tests marked with a `+` will be executed when `./startApprovalTests.sh` is used the next time.
Tests marked with a `-` are excluded from the execution.
If a test class is marked with `+` then all tests of the test class are selected for execution,
except those marked with `-`.
Inversely, if a test class is marked with `-` then all tests of the test class are excluded from
execution, except those marked with `+`.
All failed or aborted tests are saved into file `./allFailedOrAborted.txt` (default name).
This file then can be used to run all or selected of the failed or aborted tests.
Run `java -jar ./bin/pkits-testsuite-exec.jar --help` for more information.

## Testing methodology

Our concept of testing incorporates the following principles:

* An OCSP responder is simulated and the test object is configured to use this instead (over the
  TSL).
* A TSL provider is simulated and the test object is configured to use this instead (over the TSL).
* A use case is triggered that provokes the check of an end-entity certificate.

Both simulators are configured for each test case and each used certificate individually and
reset afterward. This means that only during the test execution, the simulators answer requests
with a useful response. In between tests, requests are answered with a http 500 error code.

Every request the test object does to one of the simulators contains the sequence number of the last
correctly processed TSL. This serves as a check to evaluate the trust store in the test object.

Mainly, we use two different kinds of test data

1. A default end-entity certificate to trigger a use case for the corresponding test object (e.g., a
   TLS handshake) signed by a SUB-CA.
2. An alternative end-entity certificate signed by another SUB-CA. This alternative SUB-CA
   certificate is not every time in the TSL.

This way it can be checked if the trust store changed, and if a TSL was processed as expected.

Every test is independent and all tests can be executed in any order. However, there is one test
that is expected to disable the PKI functionality of the test object by importing a TSL which
expires a few moments after generation: `verifyExpiredTslInSystem()`. This is why the test suite
executes this test case always at the end.

## Running PKITS Components in Docker Containers

It is possible to containerize the components of the test suite (OCSP Responder, TSL Provider).
You can start them _localy_ as docker compose services. See these configuration files:

* [docker-compose-base.yml](docker-compose-base.yml)
* [docker-compose-deployLocal.yml](docker-compose-deployLocal.yml)

The following scripts from directory ./docs/docker/ can be used to build, run and use the container
images:

* [docker1_BuildImages.sh](docs%2Fdocker%2Fdocker1_BuildImages.sh)
* [docker2_StartContainers.sh](docs%2Fdocker%2Fdocker2_StartContainers.sh)
* [docker3_RunTests.sh](docs%2Fdocker%2Fdocker3_RunTests.sh)

Docker-Desktop 4.21.1 (with Docker Engine 24.0.2 and Docker Compose: v2.19.1) was used for testing
this functionality.

Make sure that your particular configuration file (`pkits.yml`) is used by the `docker3_RunTests.sh`
script.

## Building the project

Building the project requires at least Java 17, [Apache
Maven 3.6.3](https://maven.apache.org/index.html) and a local or online accessible Maven Central
cache.

The following commands will build the sources and generate a zip package like the one from the
release.

```bash
mvn clean package 
```

You can find the zip package in the directory `./out/pki-testsuite-x.x.x.zip`.

## Contact

For questions or issues, feel free to open a
ticket: https://service.gematik.de/servicedesk/customer/portal/36
If you are not a registered user yet, you can use the following contact
formular: https://www.gematik.de/kontakt/kontaktformular

## Versioning

Versions below 1.0.0 are considered incomplete. For every version beyond 1.0.0, every major Version
will have a code name naming a chemical element in alphabetical order. If more than one element
exists with the corresponding letter, the element with lower atomic number is chosen. So the first
1.0.0 release will be called Aluminum.

## Remark

Cryptographic private keys used in this project are solely used in test resources for the purpose of
(unit) tests. We are fully aware of the content and meaning of the test data. We never publish
productive data.

## Know issues

- there are no tests for an invalid keyUsages for the UseCase certificate
- there are no tests for an invalid extended keyUsages the UseCase certificate

## License

Copyright 2023 gematik GmbH

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in
compliance with the License.

See the [LICENSE](./LICENSE) for the specific language governing permissions and limitations under
the License.

Unless required by applicable law the software is provided "as is" without warranty of any kind,
either express or implied, including, but not limited to, the warranties of fitness for a particular
purpose, merchantability, and/or non-infringement. The authors or copyright holders shall not be
liable in any manner whatsoever for any damages or other claims arising from, out of or in
connection with the software or the use or other dealings with the software, whether in an action of
contract, tort, or otherwise.

The software is the result of research and development activities, therefore not necessarily quality
assured and without the character of a liable product. For this reason, gematik does not provide any
support or other user assistance (unless otherwise stated in individual cases and without
justification of a legal obligation). Furthermore, there is no claim to further development and
adaptation of the results to a more current state of the art.

Gematik may remove published results temporarily or permanently from the place of publication at any
time without prior notice or justification.
