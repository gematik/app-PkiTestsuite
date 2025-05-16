#!/usr/bin/env bash
#set -x

# desc: checks common certificate types if they are valid for at least xxx days
# param1: directory to recursively check files in, if not given current directory is set
# known issues: files which contain p12.pem are not checked

# function to get date OS dependent, handles both the current date (now) and any specific date string provided to it
get_date() {
    if [[ "$OSTYPE" == "darwin"* ]]; then
        # macOS (BSD date): handle "now" or any date format
        if [[ "$1" == "now" ]]; then
            date "+%s"  # Return current timestamp
        elif [[ "$1" =~ ^[0-9]+$ ]]; then
            # If the input is a number (Unix timestamp), return it as is
            echo "$1"
        else
            # macOS: Try parsing different formats
            date -j -f "%b %d %H:%M:%S %Y %Z" "$1" "+%s" 2>/dev/null || \
            date -j -f "%Y-%m-%d %H:%M:%S" "$1" "+%s"  # Fallback to another format
        fi
    else
        # Linux (GNU date): handle "now" or any date format
        if [[ "$1" == "now" ]]; then
            date "+%s"  # Return current timestamp
        elif [[ "$1" =~ ^[0-9]+$ ]]; then
            # If the input is a number (Unix timestamp), return it as is
            echo "$1"
        else
            date -d "$1" "+%s"  # Parse specific date
        fi
    fi
}

SEARCH_FOLDER=$1
validitySeconds=3888000; # 45 days == 3888000; 90 day = 7776000; 180 days = 15552000;
expCertFound=0;
now=$(get_date "now")

if [[ -z $SEARCH_FOLDER ]]; then
        SEARCH_FOLDER="."
elif ! ([[ -d $SEARCH_FOLDER ]]); then
    echo "$SEARCH_FOLDER is not a valid directory"
    exit 1;
fi

function dateDiff() {
    # Convert both dates to Unix timestamps (seconds since epoch)
    local __d1=$(get_date "$1")
    local __d2=$(get_date "$2")

    # Calculate the difference in seconds
    echo $(( __d1 - __d2 ))
}

function printStatus(){
    local __errorLevel=$1
    local __file=$2
    if [ $__errorLevel -ne 0 ]; then
        echo $__file
        expCertFound=1
    fi
}

echo "Checking folder $SEARCH_FOLDER recursively for expired certificates..."

shopt -s globstar
for file in $SEARCH_FOLDER/**/*; do
    # skipping "Production" folder as it contains only examples for producing certs
    if [[ ("$file" == *"Production/"*) ]]; then
        continue
    fi
    # make filename lower case
    cert=${file,,}

    # if filename does not contain the string "expired"
    if [[ ("$cert" == *"expired"*) && ! ("$cert" == *"expired_ta"*)]]; then # exclude valid ee from expired ca
        echo skipping file $cert, because it is expired on purpose \(name suggests so\)
        continue
    fi
    # if filename contains pem and not p12 (.p12.pem) etc. 
    if [[ ("$cert" == *"pem") && ! ("$cert" == *"p12.pem") && ! ("$cert" == *"prv.pem") && ! ("$cert" == *"pub.pem") ]]; then
        # check validity
        openssl x509 -checkend $validitySeconds -noout -in "$file"  >/dev/null
        printStatus $? $file
        # in case of not yet valid certs...
        if [[ ("$cert" == *"yet"*) ]]; then 
            notBefore=$(openssl x509 -dates -noout -in $file | grep notBefore | awk 'BEGIN {FS = "=" } ;{print $2}')
            if [[ $(dateDiff "$notBefore" "$now") -le $validitySeconds ]]; then
                printStatus 1 $file
            fi
        fi
    fi
    if [[ "$cert" =~ (der|cer|crt)$ ]]; then
        openssl x509 -checkend $validitySeconds -noout -in "$file" -inform der >/dev/null
        printStatus $? $file
        # in case of not yet valid certs...
        if [[ ("$cert" == *"yet"*) ]]; then 
            notBefore=$(openssl x509 -dates -noout -in $file -inform der | grep notBefore | awk 'BEGIN {FS = "=" } ;{print $2}')
            if [[ $(dateDiff "$notBefore" "$now") -le $validitySeconds ]]; then
                printStatus 1 $file
            fi
        fi
    fi
    # if filename ends with p12
    if [[ "$cert" == *"p12" ]]; then
        openssl pkcs12 -in "$file" -nodes -nokeys -passin pass:00 -legacy | openssl x509 -checkend $validitySeconds -noout >/dev/null
        printStatus $? $file
        # in case of not yet valid certs...
        if [[ ("$cert" == *"yet"*)  && ! ("$cert" == *"not-yet-valid_ta"*) ]]; then # exclude valid ee from not yet valid ca
            notBefore=$(openssl pkcs12 -in "$file" -nodes -nokeys -passin pass:00 -legacy | openssl x509 -dates -noout | grep notBefore | awk 'BEGIN {FS = "=" } ;{print $2}')
            if [[ $(dateDiff "$notBefore" "$now") -le $validitySeconds ]]; then
                printStatus 1 $file
            fi
        fi
    fi
done

echo "...done!"
if [[ $expCertFound -eq 1 ]]; then 
    echo "Certificates will expire in less than $((validitySeconds/86400)) days, or are already expired.";
fi
exit $expCertFound
