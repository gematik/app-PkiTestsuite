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

package de.gematik.pki.pkits.testsuite.runner;

import de.gematik.pki.pkits.testsuite.config.Afo;
import java.lang.reflect.Method;
import lombok.AllArgsConstructor;
import lombok.Getter;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.builder.CompareToBuilder;
import org.apache.commons.lang3.builder.HashCodeBuilder;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.params.ParameterizedTest;

@AllArgsConstructor
@Getter
public class CustomTestInfo implements Comparable<CustomTestInfo> {

  Class<?> clazz;
  Method method;
  String displayName;

  Afo[] afos;

  public String getMethodName() {
    return method.getName();
  }

  public String getClassName() {
    return clazz.getCanonicalName();
  }

  String getSimpleClassName() {
    return clazz.getSimpleName();
  }

  @Override
  public int compareTo(final CustomTestInfo o) {
    return new CompareToBuilder()
        .append(this.getClassName(), o.getClassName())
        .append(this.getMethodName(), o.getMethodName())
        .toComparison();
  }

  @Override
  public boolean equals(final Object obj) {

    if (obj == this) {
      return true;
    }

    if (!(obj instanceof CustomTestInfo)) {
      return false;
    }

    return compareTo((CustomTestInfo) obj) == 0;
  }

  @Override
  public int hashCode() {
    return new HashCodeBuilder(17, 37).append(getClassName()).append(getMethodName()).toHashCode();
  }

  public boolean matches(final InputTestInfo inputTestInfo) {
    final boolean sameClassName =
        StringUtils.isBlank(inputTestInfo.methodName) && sameClassName(inputTestInfo.className);

    final boolean sameMethodName = sameMethodName(inputTestInfo.methodName);

    return sameClassName || sameMethodName;
  }

  boolean sameClassName(final String className) {
    return StringUtils.equalsAny(className, getSimpleClassName(), getClassName());
  }

  boolean sameMethodName(final String methodName) {
    return method.getName().equals(methodName);
  }

  public boolean isParameterizedTest() {
    return method.getAnnotation(ParameterizedTest.class) != null;
  }

  public boolean isDisabled() {
    return method.getAnnotation(Disabled.class) != null;
  }

  @Override
  public String toString() {
    return "CustomTestInfo{class='%s', method='%s', displayName='%s'}"
        .formatted(getClassName(), getMethodName(), displayName);
  }
}
