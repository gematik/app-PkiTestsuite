/*
 *  Copyright 2023 gematik GmbH
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

package de.gematik.pki.pkits.testsuite.reporting;

import de.gematik.pki.pkits.common.PkiCommonException;
import de.gematik.pki.pkits.testsuite.config.ParameterDescription;
import de.gematik.pki.pkits.testsuite.config.TestSuiteConfig;
import de.gematik.pki.pkits.testsuite.reporting.ListApprovalTestsAndAfos.ExecutionMode;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;

@Slf4j
public class ListParameters {

  private static final Path ALL_PKITS_PARAMETERS_FILE = Path.of("./docs/all_pkits_parameters.yml");

  @Getter
  public static class YamlLine {
    private final int level;
    private final String path;
    private final Field field;
    private final boolean isEnd;
    private final String description;
    private final boolean withDefault;

    public YamlLine(final int level, final String path, final Field field, final boolean isEnd) {
      this.level = level;
      this.path = path;
      this.field = field;
      this.isEnd = isEnd;

      final ParameterDescription parameterDescription =
          this.field.getAnnotation(ParameterDescription.class);
      if (parameterDescription != null) {
        this.description = parameterDescription.description();
        this.withDefault = parameterDescription.withDefault();
      } else {
        this.description = "";
        this.withDefault = false;
      }
    }

    public boolean hasDescription() {
      return StringUtils.isNotBlank(description);
    }

    public boolean isFieldStringLike() {
      final Class<?> fieldClazz = field.getType();
      return fieldClazz.equals(String.class) || fieldClazz.equals(Path.class);
    }

    private String getIndentForFieldWithValue(final String valueStr) {
      return StringUtils.repeat("  ", level) + field.getName() + ":" + valueStr;
    }

    public String getLineForYaml() {

      if (!isEnd) {
        return "\n" + getIndentForFieldWithValue("");
      }

      final String valueStr;
      final Class<?> clazz = field.getDeclaringClass();
      if (withDefault) {
        try {
          final Object obj = clazz.getDeclaredConstructor().newInstance();
          field.setAccessible(true); // NOSONAR squid:S3011

          final Object value = field.get(obj);
          if (isFieldStringLike()) {
            valueStr = " \"%s\"".formatted(value).replace("\\", "/");
          } else {
            valueStr = " " + value;
          }
        } catch (final NoSuchMethodException
            | InvocationTargetException
            | InstantiationException
            | IllegalAccessException e) {
          throw new PkiCommonException(
              "Cannot generate instance of " + clazz.getCanonicalName(), e);
        }

      } else {
        if (isFieldStringLike()) {
          valueStr = " \"HasToBeDefined_%s\"".formatted(field.getName());
        } else {
          valueStr = " HasToBeDefined_" + field.getName();
        }
      }

      return getIndentForFieldWithValue(valueStr);
    }

    public String getLineForYamlWithDescription(final int spacePads) {
      if (!isEnd) {
        return getLineForYaml();
      }

      final String formatStr = String.format("%%__-%d__s # %%s", spacePads).replace("_", "");
      if (hasDescription()) {
        return formatStr.formatted(getLineForYaml(), description);
      } else {
        return formatStr.formatted(getLineForYaml(), "");
      }
    }
  }

  static boolean isEnd(final Class<?> fieldClazz) {
    return fieldClazz.isPrimitive()
        || fieldClazz.equals(String.class)
        || fieldClazz.equals(Path.class)
        || fieldClazz.equals(Integer.class);
  }

  public static List<YamlLine> getFields(
      final int level, final String parentPath, final Class<?> clazz) {
    final Field[] fields = clazz.getDeclaredFields();

    final List<YamlLine> yamlLines = new ArrayList<>();
    for (final Field field : fields) {

      final Class<?> fieldClazz = field.getType();
      final String path = parentPath + "." + field.getName();
      final String message =
          "field %s of type %s in class %s: processing of the type is not implemented"
              .formatted(field.getName(), fieldClazz.getCanonicalName(), clazz.getCanonicalName());

      if (isEnd(fieldClazz)) {
        yamlLines.add(new YamlLine(level, path, field, true));

      } else if (fieldClazz.getCanonicalName().startsWith("de.gematik")) {
        yamlLines.add(new YamlLine(level, path, field, false));
        yamlLines.addAll(getFields(level + 1, path, fieldClazz));

      } else if (fieldClazz.isArray()) {
        throw new IllegalArgumentException(message);

      } else if (fieldClazz.isEnum()) {

        throw new IllegalArgumentException(message);

      } else {
        throw new IllegalArgumentException(message);
      }
    }

    return yamlLines;
  }

  private static void saveOrVerifyForAllPkitsParameters(final ExecutionMode executionMode) {
    final List<YamlLine> yamlLines = getFields(0, ".", TestSuiteConfig.class);

    final int padSize = 90;

    final List<String> lines =
        yamlLines.stream()
            .map(yamlLine -> yamlLine.getLineForYamlWithDescription(padSize))
            .toList();

    final String generatedContent = String.join("\n", lines) + "\n";

    ListApprovalTestsAndAfos.saveOrVerify(
        ALL_PKITS_PARAMETERS_FILE, generatedContent, executionMode);
  }

  public static void main(final String[] args) {

    if (ListApprovalTestsAndAfos.isToVerify(args)) {
      saveOrVerifyForAllPkitsParameters(ExecutionMode.VERIFY);
    }

    if (ListApprovalTestsAndAfos.isToGenerate(args)) {
      saveOrVerifyForAllPkitsParameters(ExecutionMode.SAVE);
    }
  }
}
