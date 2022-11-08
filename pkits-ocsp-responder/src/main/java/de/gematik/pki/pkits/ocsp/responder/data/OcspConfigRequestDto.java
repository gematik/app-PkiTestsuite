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

import static de.gematik.pki.pkits.common.PkitsConstants.NOT_CONFIGURED;

import java.io.Serial;
import java.io.Serializable;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.NonNull;
import lombok.Setter;
import org.apache.commons.lang3.ObjectUtils;

@Getter
@Setter
@NoArgsConstructor
public class OcspConfigRequestDto implements Serializable {

  @Serial private static final long serialVersionUID = 1281849381050153864L;
  private String bearerToken;
  private OcspResponderConfigDto ocspResponderConfigDto;

  public OcspConfigRequestDto(
      @NonNull final String bearerToken, final OcspResponderConfigDto ocspResponderConfigDto) {
    this.bearerToken = bearerToken;
    this.ocspResponderConfigDto = ocspResponderConfigDto;
  }

  @Override
  public String toString() {
    final Object message = ObjectUtils.defaultIfNull(ocspResponderConfigDto, NOT_CONFIGURED);
    return String.format("bearerToken: %s, ocspRespConfiguration: %s", bearerToken, message);
  }
}
