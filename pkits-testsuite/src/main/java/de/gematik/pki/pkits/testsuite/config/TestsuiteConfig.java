/*
 * Copyright (c) 2022 gematik GmbH
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

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class TestsuiteConfig {

  private ClientConfig client;

  @JsonProperty("testobject")
  private TestobjectConfig testObject;

  @JsonProperty("ocspresponder")
  private OcspResponderConfig ocspResponder;

  @JsonProperty("tslprovider")
  private TslProviderConfig tslProvider;

  @JsonProperty("testsuiteParameter")
  private TestsuiteParameter testsuiteParameter;
}
