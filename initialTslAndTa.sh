#!/bin/bash

TSL_DAYS=90

function show_help {
    echo -e "\nUsage: ./initialTslAndTa.sh [OPTIONS]\n"
    echo "Options:"
    echo "  --config /path/to/config.yml   Specify the path to a custom configuration file."
    echo "  --tslDays <value>              Set the number of days until the next TSL update (default: 90)."
    echo "  --help                         Show this help message."
    echo -e "\nExamples:"
    echo "  ./initialTslAndTa.sh --config /path/to/config.yml --tslDays 45"
    echo "  ./initialTslAndTa.sh --tslDays 30"
    echo -e "\nIf no --config is provided, the default configuration file './config/pkits.yml' will be used."
}

# Parameter auslesen
while [[ "$#" -gt 0 ]]; do
    case $1 in
        --config) PARAM_PKITS_CONFIG="$2"; shift ;;
        --tslDays) TSL_DAYS="$2"; shift ;;
        --help) show_help; exit 0 ;;
        *) echo "Unbekannter Parameter: $1"; exit 1 ;;
    esac
    shift
done

if [ -n "$PARAM_PKITS_CONFIG" ]; then
  # given config
  if [ ! -f "$PARAM_PKITS_CONFIG" ]; then
    echo -e "\n\nConfig file <$PARAM_PKITS_CONFIG> does not exist.\n\n"
    exit 1
  fi
  pkitsConfig="-DpkitsConfig=$PARAM_PKITS_CONFIG"
  echo -e "\n\nProvided config file at $PARAM_PKITS_CONFIG will be used.\n\n"
else
  # fallback
  DEFAULT_PKITS_CONFIG='./config/pkits.yml'
  if [ ! -f "$DEFAULT_PKITS_CONFIG" ]; then
    echo -e "\n\nDefault config file <$DEFAULT_PKITS_CONFIG> does not exist.\n\n"
    exit 1
  fi
  pkitsConfig="-DpkitsConfig=$DEFAULT_PKITS_CONFIG"
  echo -e "\n\nDefault config file at $DEFAULT_PKITS_CONFIG will be used.\n\n"
fi

customFileNamePostfix=-Dlog4j2.customFileNamePostfix=_`date "+%Y%m%d_%H%M%S"`

java -Dtsl.days=$TSL_DAYS $customFileNamePostfix  $pkitsConfig  -jar ./bin/pkits-testsuite-exec.jar --tests-names "InitialTestDataTest#buildInitialTslAndTa"
if [ $? -eq 0 ]; then
  printf "...done!"
  exit 0
else
  exit 1
fi
