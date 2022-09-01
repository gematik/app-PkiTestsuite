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

package de.gematik.pki.pkits.ocsp.responder.data;

import java.io.Serial;
import java.io.Serializable;
import java.util.Objects;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@AllArgsConstructor
@NoArgsConstructor
@Getter
@Setter
public class OcspConfigRequestDto implements Serializable {

  @Serial private static final long serialVersionUID = 1281849381050153864L;
  private String bearerToken;
  private OcspResponderConfigDto ocspResponderConfigDto;

  @Override
  public String toString() {
    Objects.requireNonNull(bearerToken, "bearerToken must not be null");
    Objects.requireNonNull(ocspResponderConfigDto, "ocspRespConfiguration must not be null");
    return String.format(
        "bearerToken: %s, ocspRespConfiguration: %s", bearerToken, ocspResponderConfigDto);
  }
}
