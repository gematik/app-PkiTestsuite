/*
 * Copyright (Date see Readme), gematik GmbH
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

package de.gematik.pki.pkits.sut.server.sim.exceptions;

import java.io.Serial;

/** Exception thrown by a test object simulation (TOS) */
public class TosException extends RuntimeException {

  @Serial private static final long serialVersionUID = -2007049145074855861L;

  public TosException(final String message) {
    super(message);
  }

  public TosException(final String message, final Exception e) {
    super(message, e);
  }
}
