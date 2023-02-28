/*
 * Copyright (c) 2023 gematik GmbH
 * 
 * Licensed under the Apache License, Version 2.0 (the License);
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *     http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an 'AS IS' BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package de.gematik.pki.pkits.testsuite.config;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class TestSuiteParameter {

  @ParameterDescription(
      withDefault = true,
      description = "Execute smoke test (TSL and use case including OCSP) before each test.")
  boolean performInitialState = true;

  @ParameterDescription(
      withDefault = true,
      description =
          "Capture network traffic in pcap file format. Configuration of interface to sniff on is"
              + " done by parameter \"captureInterface\" If OCSP responder and TSL provider are not"
              + " started externally, sniffing on there interfaces is activated as well.")
  boolean captureNetworkTraffic = false;

  @ParameterDescription(
      description = "IP address of an interface to sniff communication with the test object from.")
  String captureInterface;

  OcspSettings ocspSettings = new OcspSettings();
  TslSettings tslSettings = new TslSettings();
}
