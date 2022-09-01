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

package de.gematik.pki.pkits.sut.server.sim.controllers;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;

@SpringBootTest
@AutoConfigureMockMvc
class SSLTestControllerTest {

  @Autowired private MockMvc mockMvc;

  @Test
  void greeting() throws Exception {
    final MockHttpServletRequestBuilder requestBuilder = MockMvcRequestBuilders.get("/ssl-test");
    assertThat(mockMvc.perform(requestBuilder).andReturn().getResponse().getContentAsString())
        .contains(":-)");
  }

  @Test
  void greetingFails() throws Exception {
    final MockHttpServletRequestBuilder requestBuilder = MockMvcRequestBuilders.get("/fail");
    assertThat(mockMvc.perform(requestBuilder).andReturn().getResponse().getStatus())
        .isEqualTo(404);
  }
}
