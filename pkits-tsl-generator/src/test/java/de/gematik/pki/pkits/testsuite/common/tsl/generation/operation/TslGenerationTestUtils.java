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

package de.gematik.pki.pkits.testsuite.common.tsl.generation.operation;

import de.gematik.pki.gemlibpki.tsl.TslInformationProvider;
import de.gematik.pki.gemlibpki.tsl.TslReader;
import de.gematik.pki.gemlibpki.tsl.TspService;
import de.gematik.pki.gemlibpki.utils.ResourceReader;
import eu.europa.esig.trustedlist.jaxb.tsl.TSPServiceType;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import lombok.extern.slf4j.Slf4j;
import org.xmlunit.builder.DiffBuilder;
import org.xmlunit.diff.Diff;

@Slf4j
public class TslGenerationTestUtils {

  public static boolean documentsAreEqual(final Object actual, final Object expected) {
    final Diff docDiff =
        DiffBuilder.compare(actual)
            .withTest(expected)
            .withNodeFilter( // ignore element "Signature" (there are new namespaces)
                node -> !node.getNodeName().contains(":Signature"))
            .ignoreWhitespace()
            .build();
    if (docDiff.hasDifferences()) {
      log.info("Diffs: {}", docDiff.getDifferences());
    }
    return !docDiff.hasDifferences();
  }

  public static boolean duplicatedTspServicesFound(final List<TspService> tspServices) {
    return duplicatedTspServicesTypesFound(
        tspServices.stream().map(TspService::getTspServiceType).toList());
  }

  public static boolean duplicatedTspServicesTypesFound(
      final List<TSPServiceType> tspServiceTypes) {
    final Map<String, Long> tspServicesEntriesFound =
        tspServiceTypes.stream()
            .collect(
                Collectors.groupingBy(
                    tspService ->
                        tspService
                            .getServiceInformation()
                            .getServiceName()
                            .getName()
                            .get(0)
                            .getValue(),
                    Collectors.counting()));

    final List<String> dups =
        tspServicesEntriesFound.entrySet().stream()
            .filter(entry -> entry.getValue() > 1)
            .map(Map.Entry::getKey)
            .toList();

    return !dups.isEmpty();
  }

  public static List<TspService> getTspServices(final String tslFilename) {
    return new TslInformationProvider(
            TslReader.getTslUnsigned(
                ResourceReader.getFilePathFromResources(tslFilename, TslGenerationTestUtils.class)))
        .getTspServices();
  }
}
