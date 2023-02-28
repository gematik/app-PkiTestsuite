#!/bin/bash

prepareReportExtraFiles() {

set -x

rm ./pkits-testsuite/src/site/markdown/*

mkdir ./pkits-testsuite/src/site/markdown/

cp ./out/logs/pkits-testsuite-test.log  ./pkits-testsuite/src/site/markdown/pkits-testsuite-test.log.md
cp ./config/pkits.yml                   ./pkits-testsuite/src/site/markdown/pkits.yml.md

# escape special characters
sed -ir 's/[][`*_{}()#+!\<-]/\\\0/g'    ./pkits-testsuite/src/site/markdown/pkits-testsuite-test.log.md
sed -ir 's/[][`*_{}()#+!\<-]/\\\0/g'    ./pkits-testsuite/src/site/markdown/pkits.yml.md

# replace leading spaces and tabs
sed -i -E 's/^[ \t]+/\&nbsp;\&nbsp;/g'         ./pkits-testsuite/src/site/markdown/pkits-testsuite-test.log.md
sed -i -E 's/^    /&nbsp;&nbsp;&nbsp;&nbsp;/g' ./pkits-testsuite/src/site/markdown/pkits.yml.md
sed -i -E 's/^  /\&nbsp;\&nbsp;/g'             ./pkits-testsuite/src/site/markdown/pkits.yml.md


# replace every line break with two line breaks
sed -ir 's/$/\n/g'                      ./pkits-testsuite/src/site/markdown/pkits-testsuite-test.log.md
sed -ir 's/$/\n/g'                      ./pkits-testsuite/src/site/markdown/pkits.yml.md

set +x
}

whole_current_class=""
current_class=""
maven_tests_separator=""
maven_tests=""

test_counter=0

while IFS= read -r line
do
  col0=$(cut -d$'\t' -f1 <<< "$line")
  col1=$(cut -d$'\t' -f2 <<< "$line")
  
  if [[ "$col1" == "" ]];
  then
    continue
  fi
  
  if [[ "$col1" == de.* ]];
  then
    current_class="${col1}"
    whole_current_class=""

    if [[ "$col0" == "+" ]];
    then
      whole_current_class="+"
    fi

  elif [ "${col0}" == "+" ] || ( [ "${whole_current_class}" == "+" ] &&  [ "${col0}" != "-" ] )
  then
    subcols=( $col1 )
    col_method=${subcols[0]}
    echo "${col0}  --  ${col_method}" -- "${current_class}"
    maven_tests="${maven_tests}${maven_tests_separator}${current_class}#${col_method}"
    maven_tests_separator=", "
    test_counter=$(( test_counter + 1 ))
  fi
done < allTests.txt

if [ "$test_counter" -eq "0" ]; then
  echo -e "\n\nNo Test(s) zum Ausführen wurden angegeben in allTests.txt\n\n" >>/dev/stderr
  exit 1
fi


echo -e "\n\n$test_counter Test(s) zum Ausführen wurden angegeben in allTests.txt\n\n"

echo "maven_tests=${maven_tests}"



printf "Projekt bauen und Tests ausführen...\n\n\n"
set -x
mvn clean install "-Dit.test=$maven_tests" "$@"
set +x
printf "mache den Report schön...\n"
mvn site -DgenerateReports=false >>/dev/null

prepareReportExtraFiles >>/dev/null

mvn pdf:pdf -pl pkits-testsuite >>/dev/null
printf "...fertig!"
