/*
 * Copyright (Change Date see Readme), gematik GmbH
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
 *
 * ******
 *
 * For additional notes and disclaimer from gematik and in case of changes by gematik find details in the "Readme" file.
 */

package de.gematik.pki.pkits.testsuite.runner;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.jar.Attributes;
import java.util.jar.Attributes.Name;
import org.junit.jupiter.api.Test;

class PkitsTestsuiteRunnerTest {

  @Test
  void getManifestAttributeShouldHandleNullAndBlankValues() {
    final Attributes attributes = new Attributes();
    attributes.put(Name.IMPLEMENTATION_TITLE, "  PKI Test Suite  ");
    attributes.put(Name.IMPLEMENTATION_VERSION, "   ");

    assertThat(PkitsTestsuiteRunner.getManifestAttribute(null, Name.IMPLEMENTATION_TITLE)).isNull();
    assertThat(PkitsTestsuiteRunner.getManifestAttribute(attributes, Name.IMPLEMENTATION_TITLE))
        .isEqualTo("PKI Test Suite");
    assertThat(PkitsTestsuiteRunner.getManifestAttribute(attributes, Name.IMPLEMENTATION_VERSION))
        .isNull();
  }

  @Test
  void getPkiTestsuiteBannerShouldNotContainNullValues() {
    final String banner = PkitsTestsuiteRunner.getPkiTestsuiteBanner();

    assertThat(banner).doesNotContain("\nnull\n").doesNotEndWith("\nnull");
    assertThat(banner).contains(PkitsTestsuiteRunner.DEFAULT_BANNER_TITLE);

    final String[] lines = banner.split("\\R");
    assertThat(lines[lines.length - 1]).isNotBlank().isNotEqualTo("null");
  }
}
