#!/usr/bin/env bash
#set -x 

# desc: checks TSLs if they are not older then 180 days
# param1: directory to recursevely check xml-files in, if not given current directory is set
# copyright: 2023 gematik

if ! command -v xmllint &> /dev/null
then
    echo "xmllint could not be found, exiting"
    exit
fi


SEARCH_FOLDER=$1
expTslFound=0;
now=$(date -d 'now')
validityDays=180;

if [[ -z $SEARCH_FOLDER ]]; then
        SEARCH_FOLDER="."
    else if !([[ -d $SEARCH_FOLDER ]]); then
        echo "$SEARCH_FOLDER is not a valid directory"
        exit 1;
    fi
fi

datediff() {
    local __d1=$(date -d "$1" +%s)
    local __d2=$(date -d "$2" +%s)
    echo $(( (__d1 - __d2) / 86400 )) # diff in days
}

echo "Checking folder $SEARCH_FOLDER recursively for expired TSLs..."

shopt -s globstar
for file in $SEARCH_FOLDER/**/*TSL*.xml; do
  # do magic date compare stuff...
  if [[ -f "$file" ]]; then
      echo "checking $file"
      nextUpdate=$(xmllint --xpath "//*[local-name()='TrustServiceStatusList']/*[local-name()='SchemeInformation']/*[local-name()='NextUpdate']/*[local-name()='dateTime']/text()" $file);
      expDays=$(datediff "$nextUpdate" "$now");
      if [[ $expDays -ge $validityDays ]]; then
          echo "$file will expire in $expDays days"
          expTslFound=1
      fi
  fi
done

echo "...done!"
if [[ $expTslFound -eq 1 ]]; then 
    echo "TSLs will expire in less than $validityDays days, or are already expired.";
fi
exit $expTslFound
