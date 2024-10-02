/*
 * Copyright 2023 gematik GmbH
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package de.gematik.pki.pkits.ocsp.responder.data;

import java.util.ArrayList;
import java.util.List;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.NonNull;
import lombok.Setter;
import lombok.experimental.SuperBuilder;

@Getter
@Setter
@SuperBuilder(toBuilder = true)
@NoArgsConstructor
@AllArgsConstructor
public class OcspResponderConfigJsonDto extends OcspResponderConfig {

  @NonNull private List<CertificateJsonDto> certificateJsonDtos;

  public OcspResponderConfigJsonDto(final OcspResponderConfig config) {
    super(config.toBuilder());

    this.certificateJsonDtos = new ArrayList<>();
    for (CertificateDto certificateDto : config.getCertificateDtos()) {
      certificateJsonDtos.add(new CertificateJsonDto(certificateDto));
    }
  }

  public OcspResponderConfig toConfig() {

    this.certificateDtos = new ArrayList<>();
    for (CertificateJsonDto certificateJsonDto : certificateJsonDtos) {
      certificateDtos.add(certificateJsonDto.toCertificateDto());
    }
    return this;
  }
}
