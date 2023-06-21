<img align="right" width="200" height="37" src="docs/img/Gematik_Logo_Flag.png"/> <br />

# PKI Test Suite

---
<img align="left" height="150" src="docs/img/PKI_Testsuite_Blau_gematik.svg" />

This test suite is used to verify a telematic infrastructure (TI) product server of the German
health care system against gematik gemSpec_PKI specifications available
at [gematik Fachportal](https://fachportal.gematik.de/). Especially TUC_PKI_001 (TSL validation),
TUC_PKI_018 (certificate validation) and TUC_PKI_006 (OCSP response validation). It is used for
approval tests of every PKI related aspect. It is a re-development of our test suite from 2016. The
development is still ongoing [see Todo section](./README.md#todo)

Products tested by this test suite are: Intermediär, VSDM Fachdienst, VPN Zugangsdienst:
Registrierungsdienst and Konzentrator , IDP Fachdienst, KIM Fachdienst. More are coming.

---

## tl;dr

```console 
$ Download release zip file from https://github.com/gematik/app-PkiTestsuite/releases und extract it
$ cp <UserDefinedConfigfile>.yml ./config/pkits.yml (examples see: /docs/config/inttest/)
$ ./initialTslAndTa.sh (generates trust anchor and TSL in ./out for import in test object)
$ # The test object has to be started and accessible from now on.
$ ./checkInitialState.sh (acquires TSL sequence number from the test object by analysing a tsl download request and applying a use case)
$ ./startApprovalTest.sh (chose tests that shall be executed from allTests.txt)
$ # Testreport can be found in ./out directory.
```

## Technical Functionality

The test suite consists of four parts necessary for validating a PKI test object. These are
implemented as maven modules:

### 1. PKI Test Suite

This is the test suite itself. It is used to start all following modules, configure them and read
the results. It has
a [package](pkits-testsuite/src/main/java/de/gematik/pki/pkits/testsuite/approval/) with classes to
all approval tests. The test suite calls a use case
(see [Use Case Modules](./README.md#4-use-case-modules)) and expects it to either pass or fail,
depending on the test data used. If the expectation is fulfilled, the test case is passed.

### 2. TSL Provider

The TSL provider is a service that delivers TSLs to the test object.
The behaviour of this service, such as the content of a TSL offered to the test object, is
configured automatically during the test execution over a REST interface.
The TSL provider is implemented as a spring boot tomcat web server and runs as its own process.
It can be started independently or by the test suite. To start it independently one has to
set `appPath` to `"externalStartup"` in the `pkits.yml`. Address and port can be passed to the jar
via `--server.port=[port]` and `--server.address=[IpOrFqdn]`

### 3. OCSP Responder

The OCSP responder is a service to generate responses to OCSP requests sent by the test object.
The behaviour of this service is configured over a REST interface and transparent to the user.
Depending on the tests it can be configured to deliver unsigned OCSP responses, wrong cert
hashes and so on.
Similar to the TSL provider, it is implemented as a spring boot tomcat web server and runs as its
own process. It can be started independently or by the test suite. To start it independently one has
to set `appPath` to `"externalStartup"` in the `pkits.yml`. Address and port can be passed to the
jar via `--server.port=[port]` and `--server.address=[IpOrFqdn]`

### 4. Use Case Modules

At the moment there are two ways of communicating with a test object. In all scenarios the test
object has to be a server. This means, the PKI test suite acts like a client during PKI tests.

#### TLS Client

For tests against a TSL Server, the PKI testsuite has to be configured as follows:

```console
  testObject:
    type: "TlsServer"
```

This configuration will use a TSL client implementation bundled with the test suite.
It establishes a TLS handshake to a test object with a given certificate (
see [test data section](./README.md#test-data)).
Corresponding to AFOs: xxx the TLS handshake will follow the specifications from gemSpec_Krypt with
following parameter:

* TLS Version: 1.2
* cipher suites used: TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 or
  TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
* The used elliptic curves are taken from the test data delivered with the testsuite (i.e.
  brainpoolP256r1)

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

All configuration is done in one file: [/config/pkits.yml](./config/pkits.yml). You can find
examples in [/docs/config/inttest/](./docs/configs/inttest/).
The most important parameters are how to reach the test object and where to find the test data as
well as where the test object can reach the TSL- and OCSP- simulators provided by this test suite.
Paths in the `pkits.yml` are relative to the base directory. Absolute paths can be used as well.
All available parameters including a short description can be found
in [all_pkits_parameters.yml](./docs/all_pkits_parameters.yml).
As this is a YAML file remember to strictly follow the syntax.

```console 
Remember: A change of parameters that will change the TSL (i.e.OCSP responder adress and port or 
TSL provider adress an port) require a new generation of the initial TSL and import to the test 
object.
``` 

### Test Data

We deliver some test data in the directory `./testDataTemplates`. These test data are for our own
integration tests and can be used for approval tests as well. The test data form an own PKI, hence
it is not easy to create them by yourself. In later releases it is planned to generate test data on
the fly. If you use your own test data make sure that issuing certificates are added in the
[tsl templates](./testDataTemplates/tsl/) as well.

### Initial TSL and Trust Anchor

For the configuration of the test object it is necessary to initialize it with a trust space
compatible to the test suite.
For this, a convenient script is provided by the test suite:
By executing `./initialTslAndTa.sh` an initial TSL and the corresponding trust anchor are written to
the `./out` directory for import into the test object. This TSL contains the TU trust store as well,
this means, that the test object can be used during the pki tests by other services as well.

## Test Execution

The test suite expects a test object that is running and accessible over the configured IP address
and port (see [Configuration](./README.md#configuration)). Tests are executed via the
script `./startApprovalTest.sh`.
Furthermore, the [OCSP responder](./README.md#3-ocsp-responder)
and [TSL provider](./README.md#2-tsl-provider) communicate at the configured sockets (if they are
not deactivated). Logs are written to the `./out/logs` directory. Afterwards a test report is
generated in the `./out/testreport` directory.

### Smoke Test

In oder to make a quick check if everything is set up correctly, the test object can be reach by the
test suite, and to initialize the test suite with the tsl sequence number set in the test object, we
implemented a script that runs an initial test: `./checkInitialState.sh`. Within a TSL download by
the test object is exacted and afterwards a use case is triggered with a valid certificate. OCSP
requests are expected and answered correctly as well. Therefor a configured test object has to be up
and running and accessible by the testsuite and its components.

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

### Requirements

In order to run the test suite, you need a build environment according to the settings in
the [pom.xml](./pom.xml).

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

Docker-Desktop 4.17.1 with Docker Compose v2.15.1 was used for testing this functionality.

Make sure that your particular configuration file (`pkits.yml`) is used by the `docker3_RunTests.sh`
script.

## Versioning

Versions below 1.0.0 are considered incomplete. For every version beyond 1.0.0 every major Version
will have a code name naming a chemical element in alphabetical order. If more than one element
exists with the corresponding letter, the element with lower atomic number is chosen. So the first
1.0.0 release will be called Aluminium.

## Remark

Cryptographic private keys used in this project are solely used in test resources for the purpose of
(unit) tests. We are fully aware of the content and meaning of the test data. We never publish
productive data.

## License

Apache License Version 2.0

See [LICENSE](./LICENSE).

## Todo

- add generation of certificates on the fly
