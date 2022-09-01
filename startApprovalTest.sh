#!/bin/bash

whole_current_class=""
current_class=""
maven_tests_separator=""
maven_tests=""

test_counter=0

while IFS= read -r line
do
  readarray -d $'\t' -t columns < <(printf %s "$line")
  col0="${columns[0]}"
  col1="${columns[1]}"
  
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

  elif [ "${col0}" == "+" ] || [ "${whole_current_class}" == "+" ]
  then
    subcols=( $col1 )
    col_method=${subcols[0]}
    echo "${col0}  --  ${col_method}" -- "${current_class}"
    maven_tests="${maven_tests}${maven_tests_separator}${current_class}#${col_method}"
    maven_tests_separator=", "
    test_counter=$(( test_counter + 1 ))
  fi
done < allTest.txt

if [ "$test_counter" -eq "0" ]; then
  echo -e "\n\nNo Test(s) zum Ausführen wurden angegeben in allTest.txt\n\n" >>/dev/stderr
  exit 1
fi


echo -e "\n\n$test_counter Test(s) zum Ausführen wurden angegeben in allTest.txt\n\n"

echo "maven_tests=${maven_tests}"



printf "Projekt bauen und Tests ausführen...\n\n\n"
set -x
mvn clean install "-Dit.test=$maven_tests" "$@"
set +x
printf "mache den Report schön...\n"
mvn site -DgenerateReports=false >/dev/null

printf "...fertig!"
