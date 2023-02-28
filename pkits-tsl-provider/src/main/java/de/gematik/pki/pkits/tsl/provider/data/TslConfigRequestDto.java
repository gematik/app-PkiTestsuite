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

package de.gematik.pki.pkits.tsl.provider.data;

import static de.gematik.pki.pkits.common.PkitsConstants.NOT_CONFIGURED;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.NonNull;
import lombok.Setter;
import org.apache.commons.lang3.ObjectUtils;

@NoArgsConstructor
@Getter
@Setter
public class TslConfigRequestDto {

  private String bearerToken;
  private TslProviderConfigDto tslProviderConfigDto;

  public TslConfigRequestDto(
      @NonNull final String bearerToken, final TslProviderConfigDto tslProviderConfigDto) {
    this.bearerToken = bearerToken;
    this.tslProviderConfigDto = tslProviderConfigDto;
  }

  @Override
  public String toString() {
    final Object message = ObjectUtils.defaultIfNull(tslProviderConfigDto, NOT_CONFIGURED);
    return String.format("bearerToken: %s, tslProviderConfig: %s", bearerToken, message);
  }
}
