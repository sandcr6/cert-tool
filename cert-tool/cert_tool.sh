#!/bin/sh
# (C) Copyright 2016-2018 Hewlett Packard Enterprise Development LP
# cert_tool.sh
#
# usage: Usage :  described in the code below
#
# For Detail description about the available methods and usage execute below command :
# sh cert_tool.sh --help
#

# exec 2>&1
# set -x

ROOT_CERT_DAYS=3650
INTER_CERT_DAYS=3650
LEAF_CERT_DAYS=3650
CRL_EXPIRE_DAYS=1

SCRIPT_NAME=$0

setup_ca(){
    OS=`uname -s`
    echo "OPERATING SYSTEM IS $OS"
    now=`date +"%H-%M-%S"`
    CONFIG_PATH=`pwd`
    DIRECTORY_NAME=$1
    if [[ ! -e "openssl.cnf" ]];then
        echo "Not able to find openssl.cnf file in $CONFIG_PATH  location"
        exit 0
    fi

    if [[ -d "$DIRECTORY_NAME" ]]; then
        /bin/rm $DIRECTORY_NAME/*.*
    fi
    if [[ ! -d "$DIRECTORY_NAME" ]]; then
        mkdir "$DIRECTORY_NAME"
    fi

    if [[ $DIRECTORY_NAME != "csr" ]]; then
        /bin/cp "openssl.cnf" $DIRECTORY_NAME
    else
        /bin/cp "openssl_csr.cnf" $DIRECTORY_NAME
    fi
        if [[ ! -f ./$DIRECTORY_NAME/serial ]] || [[ ! -f ./$DIRECTORY_NAME/index.txt ]] ; then
            touch ./$DIRECTORY_NAME/index.txt
                touch ./$DIRECTORY_NAME/serial
                echo "1234" >> ./$DIRECTORY_NAME/serial
        fi

}

generate_leaf()
{
    export CRL_URL=$(basename $CA_CERT_FILE)
    if [[ $IP_ADDRESS_1 == "" ]]; then
        IFS=',' read -r -a array <<< "$DNS_NAME_1"
        for element in ${array[@]}
        do
            echo "$element"
            valid_ip $element
            if [[ $? -eq 0 ]]; then
                if [[ ! -z "$IP_ADDRESS" ]];then
                    IP_ADDRESS="$IP_ADDRESS,$element"
                else
                    IP_ADDRESS="$element"
                fi
            else
                if [[ ! -z "$DNS_NAME" ]];then
                    DNS_NAME="$DNS_NAME,$element"
                else
                    DNS_NAME="$element"
                fi
            fi
        done
    else
        IP_ADDRESS=$IP_ADDRESS_1
        DNS_NAME=$DNS_NAME_1
    fi
    if [[ $DNS_NAME != "" ]];then
        SUBJECT_ALT_NAMES="DNS:"$DNS_NAME
        SUBJECT_ALT_NAMES=${SUBJECT_ALT_NAMES//,/,DNS:}
    else
        SUBJECT_ALT_NAMES="DNS:$COMMON_NAME"
    fi
    if [[ $IP_ADDRESS != "" ]];then
        SUBJECT_ALT_NAME_IP=${IP_ADDRESS//,/,IP:}
        if [[ $SUBJECT_ALT_NAMES == "" ]]; then
            SUBJECT_ALT_NAME_IP="IP:"$SUBJECT_ALT_NAME_IP
        else
            SUBJECT_ALT_NAME_IP=",IP:"$SUBJECT_ALT_NAME_IP
        fi
    else
        SUBJECT_ALT_NAME_IP=""
    fi
    SUBJECT_ALT_NAMES=$SUBJECT_ALT_NAMES$SUBJECT_ALT_NAME_IP

    openssl $algo -out ./$FOLDER_NAME/$CERT_TYPE"-$COMMON_NAME".key $extras &>/dev/null
    if [ $? -ne 0 ]; then
        echo "Key generation failed.. exiting.."
        exit 1
    fi
    if [[ "$CERT_TYPE" != "client" ]];then
        export SUBJECT_ALT_NAME=$SUBJECT_ALT_NAMES
    else
        export SUBJECT_ALT_NAME="$COMMON_NAME"
    fi
    openssl req -config ./openssl.cnf -new -$hashalg -key ./$FOLDER_NAME/$CERT_TYPE"-$COMMON_NAME".key -out ./$FOLDER_NAME/$CERT_TYPE"-$COMMON_NAME".req &>/dev/null
    if [ $? -ne 0 ]; then
        echo "certificate request failed.. exiting.."
        exit 1
    fi
        if [[ ! -z "$STARTDATE" ]] && [[ ! -z "$ENDDATE" ]];then
        openssl ca -batch -config openssl.cnf  -out ./$FOLDER_NAME/$CERT_TYPE"-$COMMON_NAME".cer -startdate $STARTDATE -enddate $ENDDATE -extensions $CERT_TYPE  -cert $CA_CERT_FILE -keyfile $CA_KEY_FILE -infiles ./$FOLDER_NAME/$CERT_TYPE"-$COMMON_NAME".req  &>/dev/null
                flag=$?
    else
            openssl x509 -$hashalg -req -in ./$FOLDER_NAME/$CERT_TYPE"-$COMMON_NAME".req -CA  $CA_CERT_FILE -CAkey  $CA_KEY_FILE -set_serial $RANDOM -extfile openssl.cnf -extensions $CERT_TYPE  -days $LEAF_CERT_DAYS -outform PEM -out ./$FOLDER_NAME/$CERT_TYPE"-$COMMON_NAME".cer &>/dev/null
                flag=$?
        fi
    if [ $flag -ne 0 ]; then
        echo "certificate generation failed.. exiting.."
        exit 1
    else
        echo "======================================GENERATING ${CERT_TYPE^^} -- ===============================================================  [ OK ]  "
    fi
}

generate_ca_inter()
{
    CHAIN_DEPTH=$1
    if [[ $algo == "rsa" ]]; then
        algo="genrsa"
        extras=$KEY_LENGTH
    elif [[ $algo == "ecdsa" ]]; then
        extras="-name secp521r1 -genkey"
        algo="ecparam"
    fi
    hashalg=$HASH
    if [[ "$CREATE_CERTS" == "yes" ]]
    then
        export COMMON_NAME=$CN_PREFIX' '$ROOT_COMMON_NAME
        export SUBJECT_ALT_NAME=$CN_PREFIX' '$ROOT_COMMON_NAME
        if [[ $PATH_LEN -ne -2 ]];then
            export PATHLEN='CA:true, pathlen:'$((PATH_LEN-1))
            PATH_LEN=$((PATH_LEN-1))
        fi
        openssl $algo -out ./$FOLDER_NAME/ca.key $extras #&>/dev/null
        if [ $? -ne 0 ]; then
            echo "Key Generation for CA Root failed.. exiting.."
            exit 1
        fi
                CA_KEY_FILE="./$FOLDER_NAME/ca.key"
            openssl req -x509 -new -nodes -$hashalg -config ./$FOLDER_NAME/openssl.cnf -days $ROOT_CERT_DAYS -extensions certauth -outform PEM -key ./$FOLDER_NAME/ca.key -out ./$FOLDER_NAME/ca.cer #&>/dev/null
        if [ $? -ne 0 ]; then
            echo "Certificate generation failed.. exiting.."
            exit 1
        else
            echo "=======================GENERATING CA =================================================  [ OK ]  "
			generate_crl $FOLDER_NAME/ca.cer $FOLDER_NAME/ca.key
        fi
        CA_CERT_FILE="./$FOLDER_NAME/ca.cer"
    fi
    concatenated_cert=$FOLDER_NAME/"ca.cer"
    for (( c=1; c<$CHAIN_DEPTH; c++ ))
    do
        FILE=./$FOLDER_NAME/inter-$c.cer
        CA=$((c - 1))
        if [[ "$c" = "1" ]]
        then
            if [[ "$CREATE_CERTS" == "yes" || ! -e $FILE ]]
            then
                openssl $algo -out ./$FOLDER_NAME/inter-$c.key $extras &>/dev/null
                if [ $? -ne 0 ]; then
                    echo "Key generation failed for intermediate $c.. exiting.."
                    exit 1
                fi
                CA_KEY_FILE="./$FOLDER_NAME/inter-$c.key"
                export COMMON_NAME=$CN_PREFIX' inter-'$c
				export CRL_URL=$CN_PREFIX'-'$ROOT_COMMON_NAME
                export SUBJECT_ALT_NAME=$CN_PREFIX' inter-'$c
                if [[ $PATH_LEN -ne -2 ]];then
                    export PATHLEN='CA:true, pathlen:'$((PATH_LEN-1))
                    PATH_LEN=$((PATH_LEN-1))
                fi
                openssl req -config ./$FOLDER_NAME/openssl.cnf -new -$hashalg -key ./$FOLDER_NAME/inter-$c.key -out ./$FOLDER_NAME/inter-$c.req &>/dev/null
                if [ $? -ne 0 ]; then
                    echo "Certificate request failed for intermediate $c.. exiting.."
                    exit 1
                fi
                if [[ ! -z "$STARTDATE" ]] && [[ ! -z "$ENDDATE" ]];then
                    export FOLDER=$FOLDER_NAME
                    export DIR=$FOLDER_NAME
                    error=$(openssl ca -batch -config openssl.cnf  -out ./$FOLDER_NAME/inter-$c.cer -startdate $STARTDATE -enddate $ENDDATE -extensions v3_intermediate_ca  -cert ./$FOLDER_NAME/ca.cer -keyfile ./$FOLDER_NAME/ca.key -infiles ./$FOLDER_NAME/inter-$c.req 2>&1)
                    flag=$?
                else
                    openssl x509 -$hashalg -req -in ./$FOLDER_NAME/inter-$c.req -CA  ./$FOLDER_NAME/ca.cer -CAkey  ./$FOLDER_NAME/ca.key -set_serial $RANDOM -extfile openssl.cnf -extensions v3_intermediate_ca  -days $INTER_CERT_DAYS -outform PEM -out ./$FOLDER_NAME/inter-$c.cer &>/dev/null
                    flag=$?
                fi
                if [ $flag -ne 0 ]; then
                    echo $error
                    echo "Certificate generation failed for intermediate $c.. exiting.."
                    exit 1
                else
                    echo "====================GENERATING INTERMEDIATE NUMBER $c   ==================================================  [ OK ]  "
					generate_crl ./$FOLDER_NAME/inter-$c.cer ./$FOLDER_NAME/inter-$c.key
                fi
                CA_CERT_FILE="./$FOLDER_NAME/inter-$c.cer"
            fi
            concatenated_cert=$FOLDER_NAME/"inter-"$c".cer "$concatenated_cert
        fi

        if [[ "$c" -ne "1" ]] && [[ "$c" -ne "$CHAIN_DEPTH" ]]
        then
            if [[ "$CREATE_CERTS" == "yes" || ! -e $FILE ]]
            then
                openssl $algo -out ./$FOLDER_NAME/inter-$c.key $extras &>/dev/null
                if [ $? -ne 0 ]; then
                    echo "Key generation failed for intermediate $c.. exiting.."
                    exit 1
                fi
                CA_KEY_FILE="./$FOLDER_NAME/inter-$c.key"
                export COMMON_NAME=$CN_PREFIX' inter-'$c
				LAST_CA_TO_SIGN_CSR=$CN_PREFIX'-inter-'$c
				export CRL_URL=$CN_PREFIX'-inter-'$CA
                export SUBJECT_ALT_NAME=$CN_PREFIX' inter-'$c
                if [[ $PATH_LEN -ne -2 ]];then
                    export PATHLEN='CA:true, pathlen:'$((PATH_LEN-1))
                    PATH_LEN=$((PATH_LEN-1))
                fi
                openssl req -config ./$FOLDER_NAME/openssl.cnf -new -$hashalg -key ./$FOLDER_NAME/inter-$c.key -out ./$FOLDER_NAME/inter-$c.req &>/dev/null
                if [ $? -ne 0 ]; then
                    echo "Certificate request failed for intermediate $c.. exiting.."
                    exit 1
                fi
                if [[ ! -z "$STARTDATE" ]] && [[ ! -z "$ENDDATE" ]];then
                    export FOLDER=$FOLDER_NAME
                    export DIR=$FOLDER_NAME
                    openssl ca -batch -config openssl.cnf  -out ./$FOLDER_NAME/inter-$c.cer -startdate $STARTDATE -enddate $ENDDATE -extensions v3_intermediate_ca  -cert ./$FOLDER_NAME/inter-$CA.cer -keyfile ./$FOLDER_NAME/inter-$CA.key -infiles ./$FOLDER_NAME/inter-$c.req &>/dev/null
                    flag=$?
                else
                    openssl x509 -$hashalg -req -in ./$FOLDER_NAME/inter-$c.req -CA  ./$FOLDER_NAME/inter-$CA.cer -CAkey  ./$FOLDER_NAME/inter-$CA.key -set_serial $RANDOM -extfile openssl.cnf -extensions v3_intermediate_ca  -days $INTER_CERT_DAYS -outform PEM -out ./$FOLDER_NAME/inter-$c.cer &>/dev/null
                    flag=$?
                fi
                if [ $flag -ne 0 ]; then
                    echo "Certificate generation failed for intermediate $c.. exiting.."
                    exit 1
                else
                    echo "====================GENERATING INTERMEDIATE NUMBER $c  ==================================================  [ OK ]"
					generate_crl ./$FOLDER_NAME/inter-$c.cer ./$FOLDER_NAME/inter-$c.key
                fi
                CA_CERT_FILE="./$FOLDER_NAME/inter-$c.cer"
            fi
           concatenated_cert=$FOLDER_NAME/"inter-"$c".cer "$concatenated_cert
        fi

    done

}

generate_root_intermediates(){
    CHAIN_DEPTH=$1
    KEY_LENGTH=$2
    CREATE_CERTS=$3
    FOLDER_NAME=$4
    CN_PREFIX="$5"
    PATH_LEN=$6
    algo=$ALGORITHM

    generate_ca_inter $CHAIN_DEPTH

}

generate_chain(){
    CHAIN_DEPTH=$1
    KEY_LENGTH=$2
    CREATE_CERTS=$3
    FOLDER_NAME=$4
    CN_PREFIX="$5"
    PATH_LEN=$6
    CERT_TYPE=$8
    DNS_NAME_1=$DNS
    IP_ADDRESS_1=$IPS
    algo=$ALGORITHM
    IP_ADDRESS=''
    DNS_NAME=''
    if [[ $FLAGVAR != 1 ]]; then
        CHAIN_DEPTH=2
    fi
    CHAIN_DEPTH1=$CHAIN_DEPTH
    generate_ca_inter $((CHAIN_DEPTH1-1))
    export COMMON_NAME="$LEAF_COMMON_NAME"
    if [[ "$CHAIN_DEPTH1" != "1" ]]; then
        if [[ "$CREATE_CERTS" == "NO" ]]; then
            CHAIN_DEPTH1=$((CHAIN_DEPTH1-1))
            if [[ $CHAIN_DEPTH1 -eq 1 ]] && [[ -z $CA_CERT_FILE ]]; then
                CA_CERT_FILE="./$FOLDER_NAME/ca.cer"
                CA_KEY_FILE="./$FOLDER_NAME/ca.key"
            elif [[ $CHAIN_DEPTH1 -gt 1 ]] && [[ -z $CA_KEY_FILE ]]; then
                CA_CERT_FILE="./$FOLDER_NAME/inter-$((CHAIN_DEPTH-1)).cer"
                CA_KEY_FILE="./$FOLDER_NAME/inter-$((CHAIN_DEPTH-1)).key"
            fi
        fi
        generate_leaf
    fi
}

create_cert(){
    CA_CERT_FILE=$1
    CA_KEY_FILE=$2
    CERT_TYPE=$4
    KEY_LENGTH=$5
    FOLDER_NAME="leaf_certs"
    DNS_NAME_1=$6
    IP_ADDRESS_1=$7
    IP_ADDRESS=''
    DNS_NAME=''
    export COMMON_NAME="$3"
    algo=$ALGORITHM
    if [[ $algo == "rsa" ]]; then
        algo="genrsa"
        extras=$KEY_LENGTH
    elif [[ $algo == "ecdsa" ]]; then
        extras="-name secp521r1 -genkey"
        algo="ecparam"
    fi
    hashalg=$HASH
        if [[ ! -e $FOLDER_NAME ]];then
        mkdir $FOLDER_NAME
    fi
    generate_leaf
}

create_root_intermediates(){
    CHAIN_DEPTH=$1
    RETAIN_CA=$5
    KEY_LENGTH=$2
    CN_PREFIX="$3"
    PATH_LEN=$4
    CREATE_CERTS=$RETAIN_CA

    FOLDER_NAME="chain_certs"
    if [[ $CHAIN_DEPTH -lt 1 ]];then
       exit 0
    fi
    if [[ $RETAIN_CA == "yes" &&  -e $FOLDER_NAME ]]; then
       echo "Retaining existing CA"
       CREATE_CERTS="NO"
    elif [[ $RETAIN_CA == "no" ]]; then
        setup_ca "chain_certs"
        CREATE_CERTS="yes"
    else
        setup_ca "chain_certs"
        CREATE_CERTS="yes"
    fi
    generate_root_intermediates $CHAIN_DEPTH $KEY_LENGTH $CREATE_CERTS $FOLDER_NAME "$CN_PREFIX" $PATH_LEN
    cat $concatenated_cert > $FOLDER_NAME/"concatenated.cer"
    echo "Generated Concatenated Certificate"
    remove_newline $FOLDER_NAME "concatenated.cer"
}

create_chain(){
    CHAIN_DEPTH=$1
    KEY_LENGTH=$2
    CN_PREFIX="$3"
    PATH_LEN=$4
    RETAIN_CA=$5
    export COMMON_NAME="$6"
    CERT_TYPE=$7
    DNS_NAME=$DNS
    IP_ADDRESS=$IPS
    CREATE_CERTS=$RETAIN_CA

    FOLDER_NAME="chain_certs_leaf"
    if [[ $CHAIN_DEPTH -lt 1 ]];then
        exit 0
    fi
    if [[ $RETAIN_CA == "yes" &&  -e $FOLDER_NAME ]]; then
        echo "Retaining existing CA"
        CREATE_CERTS="NO"
    else
        setup_ca "chain_certs_leaf"
        CREATE_CERTS="yes"
    fi
    generate_chain $CHAIN_DEPTH $KEY_LENGTH $CREATE_CERTS $FOLDER_NAME "$CN_PREFIX" $PATH_LEN "$COMMON_NAME" $CERT_TYPE
    cat $FOLDER_NAME/$CERT_TYPE-"$LEAF_COMMON_NAME".cer > $FOLDER_NAME/"concatenated.cer"
    cat $concatenated_cert >> $FOLDER_NAME/"concatenated.cer"
    echo "Generated Concatenated Certificate"
    remove_newline $FOLDER_NAME "concatenated.cer"
}

generate_chain_sign_csr(){
    CHAIN_DEPTH=$1
    KEY_LENGTH=$2
    CREATE_CERTS=$3
    FOLDER_NAME=$4
    CN_PREFIX="$5"
    PATH_LEN=$6
    FILE_PATH=$7
    algo=$ALGORITHM

    SIGNED_FOLDER=$FOLDER_NAME
    CA_CERT=$CA_CERT_FILE
    CA_KEY=$CA_KEY_FILE
    if [[ -f "$CA_CERT" ]] && [[ -f "$CA_KEY" ]];then
        export COMMON_NAME=$ROOT_COMMON_NAME
		export CRL_URL=$LAST_CA_TO_SIGN_CSR
        export SUBJECT_ALT_NAME='Sample'
        result=$(openssl req -in $FILE_PATH -noout -text| grep -e DNS: -e "IP Address" | awk '{gsub("IP Address","IP",$0); print $0}')
        if [[ ! -z "${result// }" ]]; then
            export SUBJECT_ALT_NAME=$result
        else
            result=$(openssl req -in $FILE_PATH -noout -subject| awk '{split($0,a,"/"); for (key in a) if (match(a[key], /CN=*/)) {print "DNS:"substr(a[key], 4); break}}')
            export SUBJECT_ALT_NAME=$result
        fi
        result=$(openssl req -in $FILE_PATH -noout -text| grep -e DNS: -e "IP Address:" | awk '{gsub("IP Address","IP",$0); print $0}')
        server_eku=$(openssl req -in $FILE_PATH -noout -text | grep 'TLS Web Server Authentication')
        client_eku=$(openssl req -in $FILE_PATH -noout -text | grep 'TLS Web Client Authentication')
        if [[ ! -z "${server_eku// }" && ! -z "${server_eku// }" ]]; then
            CERT_TYPE="server_client"
        elif [[ ! -z "${server_eku// }" ]]; then
            CERT_TYPE="server"
        elif [[ ! -z "${client_eku// }" ]]; then
            CERT_TYPE="client"
        else
            CERT_TYPE="server"
        fi
        if [[ ! -z "$STARTDATE" ]] && [[ ! -z "$ENDDATE" ]];then
            export FOLDER=$FOLDER_NAME
            export DIR=$FOLDER_NAME
            error=$(openssl ca -batch -config openssl.cnf  -out ./$SIGNED_FOLDER/$CERT_TYPE.cer -startdate $STARTDATE -enddate $ENDDATE -extensions $CERT_TYPE  -cert $CA_CERT -keyfile $CA_KEY -infiles $FILE_PATH 2>&1)
            flag=$?
        else
            openssl x509 -$HASH -req -in $FILE_PATH  -CA  $CA_CERT -CAkey  $CA_KEY  -set_serial $RANDOM -extfile openssl.cnf -extensions $CERT_TYPE  -days $LEAF_CERT_DAYS -outform PEM -out ./$SIGNED_FOLDER/$CERT_TYPE.cer &>/dev/null
            flag=$?
        fi
        if [ $flag -ne 0 ]; then
            echo $error
            echo "Signed certificate generation failed.. exiting.."
            exit 1
        else
            echo "=======================GENERATING SIGNED CERTIFICATE=== ==============================================  [ OK ]  "
        fi
        concatenated_cert=$SIGNED_FOLDER/$CERT_TYPE".cer "$concatenated_cert
        echo "Signed"
    else
        echo "signing the CSR failed.. exiting"
    fi
}

sign_csr_chain(){
    CHAIN_DEPTH=$1
    KEY_LENGTH=$2
    CN_PREFIX="$3"
    PATH_LEN=$4
    RETAIN_CA=$5
    FILE_PATH=$6
    FOLDER_NAME="csr_chain"
    algo=$ALGORITHM
    if [[ $CHAIN_DEPTH -lt 1 ]];then
        exit 0
    fi
    if [[ $RETAIN_CA == "yes" &&  -e $FOLDER_NAME ]]; then
        echo "Retaining existing CA"
        CREATE_CERTS="NO"
    else
        setup_ca "csr_chain"
        CREATE_CERTS="yes"
    fi
    if [[ $FLAGVAR != 1 ]]; then
        CHAIN_DEPTH=2
    fi
    CHAIN_DEPTH1=$CHAIN_DEPTH
    generate_ca_inter $(($CHAIN_DEPTH-1))
    if [[ "$CHAIN_DEPTH1" != "1" ]]; then
        if [[ "$CREATE_CERTS" == "NO" ]]; then
            CHAIN_DEPTH1=$((CHAIN_DEPTH1-1))
            if [[ $CHAIN_DEPTH1 -eq 1 ]] && [[ -z $CA_CERT_FILE ]]; then
                CA_CERT_FILE="./$FOLDER_NAME/ca.cer"
                CA_KEY_FILE="./$FOLDER_NAME/ca.key"
            elif [[ $CHAIN_DEPTH1 -gt 1 ]] && [[ -z $CA_KEY_FILE ]]; then
                CA_CERT_FILE="./$FOLDER_NAME/inter-$((CHAIN_DEPTH-1)).cer"
                CA_KEY_FILE="./$FOLDER_NAME/inter-$((CHAIN_DEPTH-1)).key"
            fi
        fi
        generate_chain_sign_csr $CHAIN_DEPTH $KEY_LENGTH $CREATE_CERTS $FOLDER_NAME "$CN_PREFIX" $PATH_LEN $INPUT_FILE
    fi
    cat $concatenated_cert > $FOLDER_NAME/"concatenated.cer"
    echo "Generated Concatenated Certificate"
    remove_newline $FOLDER_NAME "concatenated.cer"
}

create_root_ca(){
    KEY_LENGTH=$1
    FOLDER=$2
    setup_ca $FOLDER

    algo=$ALGORITHM
    if [[ $algo == "rsa" ]]; then
        algo="genrsa"
        extras=$KEY_LENGTH
    elif [[ $algo == "ecdsa" ]]; then
        extras="-name secp521r1 -genkey"
        algo="ecparam"
    fi
    hashalg=$HASH

    export COMMON_NAME=$PREFIX_CN' '$ROOT_COMMON_NAME
    export SUBJECT_ALT_NAME='Sample'
    openssl $algo -out ./$FOLDER/ca.key $extras &>/dev/null
    if [ $? -ne 0 ]; then
        echo "Key Generation for CA failed.. exiting.."
        exit 1
    fi
    openssl req -x509 -new -nodes -$hashalg -config ./$FOLDER/openssl.cnf -days $ROOT_CERT_DAYS -extensions certauth -outform PEM -key ./$FOLDER/ca.key -out ./$FOLDER/ca.cer &>/dev/null
    if [ $? -ne 0 ]; then
        echo "Certificate generation for CA failed.. exiting.."
        exit 1
    else
        echo "=======================GENERATING CA=== ==============================================  [ OK ]  "
    fi
}

sign_csr(){
    FILE_PATH=$1
    KEY_LENGTH=2048
    RETAIN_CA=$2
    CA_CERT=$3
    CA_KEY=$4
    SIGNED_FOLDER="signed_certificate"
    export COMMON_NAME=$ROOT_COMMON_NAME
    export SUBJECT_ALT_NAME='Sample'
    if [[ $RETAIN_CA == "no" ]]; then
        if [[ ! -z $CA_CERT ]]; then
            setup_ca $SIGNED_FOLDER
            /bin/cp $CA_CERT $SIGNED_FOLDER/'ca.cer'
            /bin/cp $CA_KEY $SIGNED_FOLDER/'ca.key'
        else
            create_root_ca $KEY_LENGTH $SIGNED_FOLDER
        fi
    elif [[ -e $SIGNED_FOLDER && $RETAIN_CA == "yes" ]]; then
        export COMMON_NAME=$ROOT_COMMON_NAME
        export SUBJECT_ALT_NAME='Sample'
    else
        if [[ ! -z $CA_CERT ]]; then
            setup_ca $SIGNED_FOLDER
            /bin/cp $CA_CERT $SIGNED_FOLDER/'ca.cer'
            /bin/cp $CA_KEY $SIGNED_FOLDER/'ca.key'
        else
            echo "CA doesn't exist. generating CA.."
            create_root_ca $KEY_LENGTH $SIGNED_FOLDER
        fi
    fi
    result=$(openssl req -in $1 -noout -text| grep -e DNS: -e "IP Address" | awk '{gsub("IP Address","IP",$0); print $0}')
    if [[ ! -z "${result// }" ]]; then
        export SUBJECT_ALT_NAME=$result
    else
        result=$(openssl req -in $1 -noout -subject| awk '{split($0,a,"/"); for (key in a) if (match(a[key], /CN=*/)) {print "DNS:"substr(a[key], 4); break}}')
        export SUBJECT_ALT_NAME=$result
    fi
    result=$(openssl req -in $1 -noout -text| grep -e DNS: -e "IP Address:" | awk '{gsub("IP Address","IP",$0); print $0}')
    server_eku=$(openssl req -in $1 -noout -text | grep 'TLS Web Server Authentication')
    client_eku=$(openssl req -in $1 -noout -text | grep 'TLS Web Client Authentication')
    if [[ ! -z "${server_eku// }" && ! -z "${server_eku// }" ]]; then
        CERT_TYPE="server_client"
    elif [[ ! -z "${server_eku// }" ]]; then
        CERT_TYPE="server"
    elif [[ ! -z "${client_eku// }" ]]; then
        CERT_TYPE="client"
    else
        CERT_TYPE="server"
    fi
    if [[ ! -z "$STARTDATE" ]] && [[ ! -z "$ENDDATE" ]];then
        export FOLDER=$FOLDER_NAME
        export DIR=$FOLDER_NAME
        error=$(openssl ca -batch -config openssl.cnf  -out ./$SIGNED_FOLDER/$CERT_TYPE.cer -startdate $STARTDATE -enddate $ENDDATE -extensions $CERT_TYPE  -cert ./$SIGNED_FOLDER/ca.cer -keyfile ./$SIGNED_FOLDER/ca.key -infiles $FILE_PATH 2>&1)
        flag=$?
    else
        openssl x509 -$HASH -req -in $FILE_PATH  -CA  ./$SIGNED_FOLDER/ca.cer -CAkey  ./$SIGNED_FOLDER/ca.key  -set_serial $RANDOM -extfile openssl.cnf -extensions $CERT_TYPE  -days $LEAF_CERT_DAYS -outform PEM -out ./$SIGNED_FOLDER/$CERT_TYPE.cer &>/dev/null
        flag=$?
    fi
    if [ $flag -ne 0 ]; then
        echo $error
        echo "Signed certificate generation failed.. exiting.."
        exit 1
    else
        echo "=======================GENERATING SIGNED CERTIFICATE=== ==============================================  [ OK ]  "
    fi
    cat $SIGNED_FOLDER/$CERT_TYPE".cer" $SIGNED_FOLDER/"ca.cer" > $SIGNED_FOLDER/"concatenated.cer"
    echo "Generated Concatenated Certificate"
    remove_newline $SIGNED_FOLDER "concatenated.cer"
    echo "Signed"
}

create_selfsigned_servercert(){
    KEY_LENGTH=$2
    FOLDER_NAME="self_signed_server_cert"
    setup_ca $FOLDER_NAME
    export COMMON_NAME=$1
    export SUBJECT_ALT_NAME="DNS:"$1
        algo=$ALGORITHM
    if [[ $algo == "rsa" ]]; then
        algo="genrsa"
        extras=$KEY_LENGTH
    elif [[ $algo == "ecdsa" ]]; then
        extras="-name secp521r1 -genkey"
        algo="ecparam"
    fi
    hashalg=$HASH
    openssl $algo -out ./$FOLDER_NAME/self_signed_server.key $extras &>/dev/null
    if [ $? -ne 0 ]; then
        echo "Key Generation for Self Signed Server failed.. exiting.."
        exit 1
    fi
    openssl req -x509 -new -nodes -$hashalg -config ./$FOLDER_NAME/openssl.cnf -days $ROOT_CERT_DAYS -extensions selfSignedServer -outform PEM -key ./$FOLDER_NAME/self_signed_server.key -out ./$FOLDER_NAME/self_signed_server.cer &>/dev/null
    if [ $? -ne 0 ]; then
        echo "Certificate Generation for Self Signed Server failed.. exiting.."
        exit 1
    else
        echo "=======================GENERATING SELF SIGNED SERVER=== ==============================================  [ OK ]  "
    fi
    remove_newline $FOLDER_NAME "self_signed_server.cer"
}

create_selfsigned_clientcert(){
    KEY_LENGTH=$2
    FOLDER_NAME="self_signed_client_cert"
    setup_ca $FOLDER_NAME
    export COMMON_NAME=$1
    export SUBJECT_ALT_NAME=$1
        algo=$ALGORITHM
    if [[ $algo == "rsa" ]]; then
        algo="genrsa"
        extras=$KEY_LENGTH
    elif [[ $algo == "ecdsa" ]]; then
        extras="-name secp521r1 -genkey"
        algo="ecparam"
    fi
    hashalg=$HASH
    openssl $algo -out ./$FOLDER_NAME/self_signed_client.key $extras &>temp.log
        if [ $? -ne 0 ]; then
        echo "Key Generation for Self Signed client failed.. exiting.."
        exit 1
    fi
    openssl req -x509 -new -nodes -$hashalg -config ./$FOLDER_NAME/openssl.cnf -days $ROOT_CERT_DAYS -extensions selfSignedClient -outform PEM -key ./$FOLDER_NAME/self_signed_client.key -out ./$FOLDER_NAME/self_signed_client.cer &>/dev/null
        if [ $? -ne 0 ]; then
        echo "Certificate Generation for Self Signed Server failed.. exiting.."
        exit 1
    else
        echo "=======================GENERATING SELF SIGNED CLIENT=== ==============================================  [ OK ]  "
    fi
    remove_newline $FOLDER_NAME "self_signed_client.cer"
}

view_csr(){
    FILE_PATH=$1
    openssl req -in $FILE_PATH -noout -text
    if [ $? -ne 0 ]; then
        echo "view certificate request error"
        exit 1
    fi
}

view_cert(){
    FILE_PATH=$1
    openssl crl2pkcs7 -nocrl -certfile $FILE_PATH | openssl pkcs7 -print_certs -text -noout
        if [ $? -ne 0 ]; then
        echo "view certificate error"
        exit 1
    fi
}

view_crl(){
    FILE_PATH=$1
    openssl crl  -text -noout -in $FILE_PATH
    if [ $? -ne 0 ]; then
        echo "view certificate revocation list error"
        exit 1
    fi
}

generate_crl(){
    CA_CERT_FILE_PATH=$1
    CA_KEY_FILE_PATH=$2
    FILE_NAME=$(basename "$CA_CERT_FILE_PATH" ".cer")
    CRL_FOLDER="crls_"$FILE_NAME
    setup_ca $CRL_FOLDER
    touch $CRL_FOLDER/index.txt
    /bin/cp $CA_CERT_FILE_PATH ./$CRL_FOLDER/
    /bin/cp $CA_KEY_FILE_PATH ./$CRL_FOLDER/
    export COMMON_NAME=$ROOT_COMMON_NAME
    export SUBJECT_ALT_NAME='sample'
    export DIR=$CRL_FOLDER
    openssl ca -cert $CRL_FOLDER/$(basename "$CA_CERT_FILE_PATH") -keyfile $CRL_FOLDER/$(basename "$CA_KEY_FILE_PATH") -config openssl.cnf -gencrl -crldays $CRL_EXPIRE_DAYS  -out $CRL_FOLDER/crlFile-$FILE_NAME.crl &>/dev/null
    if [ $? -ne 0 ]; then
        echo "Generating Certificate Revocation List(CRL) failed.. exiting.."
        exit 1
    else
        echo "=======================GENERATING CERTIFICATE REVOCATION LIST=================================================  [ OK ]  "
    fi
}

revoke_cert(){
    CA_CERT_FILE_PATH=$1
    CA_KEY_FILE_PATH=$2
    FILE_NAME=$(basename "$CA_CERT_FILE_PATH" ".cer")
    CRL_FOLDER="crls_"$FILE_NAME
    REVOKE_CERT_PATH=$3
    if [[ ! -d $CRL_FOLDER ]]; then
        generate_crl $CA_CERT_FILE_PATH $CA_KEY_FILE_PATH
    else
        export COMMON_NAME=$ROOT_COMMON_NAME
        export SUBJECT_ALT_NAME='sample'
        export DIR=$CRL_FOLDER
    fi
    /bin/cp $REVOKE_CERT_PATH ./$CRL_FOLDER/
    openssl ca -cert $CRL_FOLDER/$(basename "$CA_CERT_FILE_PATH") -keyfile $CRL_FOLDER/$(basename "$CA_KEY_FILE_PATH") -config openssl.cnf -revoke $CRL_FOLDER/$(basename "$REVOKE_CERT_PATH") -verbose -crl_reason affiliationChanged &>/dev/null
    if [ $? -ne 0 ]; then
        echo "Revoking certificate failed.. exiting.."
        exit 1
    fi
    openssl ca -cert $CRL_FOLDER/$(basename "$CA_CERT_FILE_PATH") -keyfile $CRL_FOLDER/$(basename "$CA_KEY_FILE_PATH") -config openssl.cnf -gencrl -crldays $CRL_EXPIRE_DAYS -out $CRL_FOLDER/crlFile-$FILE_NAME.crl &>/dev/null
    if [ $? -ne 0 ]; then
        echo "Revoking certificate failed.. exiting.."
        exit 1
    else
        echo "=======================REVOKING CERTIFICATE=================================================  [ OK ] "
    fi
}

function valid_ip()
{
    local  ip=$1
    local  stat=1

    if [[ $ip =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        OIFS=$IFS
        IFS='.'
        ip=($ip)
        IFS=$OIFS
        [[ ${ip[0]} -le 255 && ${ip[1]} -le 255 \
            && ${ip[2]} -le 255 && ${ip[3]} -le 255 ]]
        stat=$?
    fi
    return $stat
}

generate_csr(){
    FOLDER="csr"
    setup_ca $FOLDER
    DNS_NAME_1=$DNS
    IP_ADDRESS_1=$IPS
    IP_ADDRESS=''
    DNS_NAME=''
    IFS=',' read -r -a array <<< "$DNS_NAME_1,$IP_ADDRESS_1"
    for element in ${array[@]}
    do
        echo "$element"
        valid_ip $element
        if [[ $? -eq 0 ]]; then
            if [[ ! -z "$IP_ADDRESS" ]];then
                IP_ADDRESS="$IP_ADDRESS,IP:$element"
            else
                IP_ADDRESS="IP:$element"
            fi
        else
            if [[ ! -z "$DNS_NAME" ]];then
                DNS_NAME="$DNS_NAME,DNS:$element"
            else
                DNS_NAME="DNS:$element"
            fi
        fi
    done
    SUBJECT_ALT_NAME=$DNS_NAME$IP_ADDRESS
    if [[ $SUBJECT_ALT_NAME != "" ]]; then
        echo "
        subjectAltName=$SUBJECT_ALT_NAME" >> ./$FOLDER/openssl_csr.cnf
    fi

    algo=$ALGORITHM
    if [[ $algo == "rsa" ]]; then
        algo="genrsa"
        extras=$KEY_LENGTH
    elif [[ $algo == "ecdsa" ]]; then
        extras="-name secp521r1 -genkey"
        algo="ecparam"
    fi
    hashalg=$HASH
    openssl $algo -out ./$FOLDER/sample_csr.key $extras &>/dev/null
    if [ $? -ne 0 ]; then
        echo "Key generation failed.. exiting.."
        exit 1
    fi
    openssl req -new -$hashalg -key ./$FOLDER/sample_csr.key -out ./$FOLDER/sample_csr.req -config ./$FOLDER/openssl_csr.cnf
    if [ $? -ne 0 ]; then
        echo "Certificate request generation failed.. exiting.."
        exit 1
    else
        echo "=======================GENERATING CERTIFICATE REQUEST=================================================  [ OK ]  "
    fi

}

cert_as_server(){
    SERVER_CERT_FILE_PATH=$1
    SERVER_CERT_KEY_PATH=$2
    if [ "$MODE" = "FIPS" ] || [ "$MODE" = "CNSA" ]; then
        xopenssl s_server -cert $SERVER_CERT_FILE_PATH -key $SERVER_CERT_KEY_PATH
    else
        openssl s_server -cert $SERVER_CERT_FILE_PATH -key $SERVER_CERT_KEY_PATH
    fi
}

cert_as_client(){
    CLIENT_CERT_FILE_PATH=$1
    ClIENT_CERT_KEY_PATH=$2
    if [ "$MODE" = "FIPS" ] || [ "$MODE" = "CNSA" ]; then
        xopenssl s_client -cert $CLIENT_CERT_FILE_PATH -key $ClIENT_CERT_KEY_PATH
    else
        openssl s_client -cert $CLIENT_CERT_FILE_PATH -key $ClIENT_CERT_KEY_PATH
    fi
}

remove_newline(){
    FOLDER=$1
    CONCATENATED=$2
    single_line_cert="single_line_cert.txt"
    if [[ -e $FOLDER/$single_line_cert ]]; then
        /bin/rm -f $FOLDER/$single_line_cert
    fi
    awk '{ sub ("\\\\$", ""); printf "%s\\n", $0 } END { print "" }' $FOLDER/$CONCATENATED >> $FOLDER/$single_line_cert
    echo "certificate concatenated to a single line"
}

pem_to_der(){
    PEM_FILE=$1
    DER_FILE=$2
    openssl x509 -outform der -in $PEM_FILE -out $DER_FILE
    if [ $? -ne 0 ]; then
        echo "pem to der conversion for certificate failed.. exiting.."
        exit 1
    fi
}

der_to_pem(){
    PEM_FILE=$2
    DER_FILE=$1
    openssl x509 -inform der -in $DER_FILE -out $PEM_FILE
    if [ $? -ne 0 ]; then
        echo "der to pem conversion for certificate failed.. exiting.."
        exit 1
    fi
}

crl_pem_to_der(){
    PEM_FILE=$1
    DER_FILE=$2
    openssl crl -outform der -in $PEM_FILE -out $DER_FILE
    if [ $? -ne 0 ]; then
        echo "pem to der conversion for certificate revocation list failed.. exiting.."
        exit 1
    fi
}

crl_der_to_pem(){
    PEM_FILE=$2
    DER_FILE=$1
    openssl crl -inform der -in $DER_FILE -out $PEM_FILE
    if [ $? -ne 0 ]; then
        echo "der to pem conversion for certificate revocation list failed.. exiting.."
        exit 1
    fi
}

pem_to_pkcs12(){
    PEM_KEY=$2
    PEM_FILE=$1
    PKCS_FILE=$3
    PASSWORD=$4
    if [[ $PASSWORD == "yes" ]]; then
        openssl pkcs12 -export -out $PKCS_FILE -inkey $PEM_KEY -in $PEM_FILE -passout pass:
        if [ $? -ne 0 ]; then
            echo "pem to pkcs12 conversion for certificate failed with default password.. exiting.."
            exit 1
        fi
    else
        openssl pkcs12 -export -out $PKCS_FILE -inkey $PEM_KEY -in $PEM_FILE
        if [ $? -ne 0 ]; then
            echo "pem to pkcs12 conversion for certificate failed.. exiting.."
            exit 1
        fi
    fi
}

pkcs12_to_pem(){
    PEM_FILE=$2
    PKCS_FILE=$1
    PASSWORD=$3
    if [[ $PASSWORD == "yes" ]]; then
        openssl pkcs12 -in $PKCS_FILE -out $PEM_FILE -passout pass: -passin pass:
        if [ $? -ne 0 ]; then
            echo "pkcs12 to pem conversion for certificate failed with default password.. exiting.."
            exit 1
        fi
    else
        openssl pkcs12 -in $PKCS_FILE -out $PEM_FILE
        if [ $? -ne 0 ]; then
            echo "pkcs12 to pem conversion for certificate failed.. exiting.."
            exit 1
        fi
    fi
}

list_available_functions(){
    echo "Available functions :    "
    echo "       1)  create_chain                           Creates root, intermediates and leaf of given depth"
    echo "                options :                         -d , -k , -r , -n , -h , -g , -l , -t , -c , -s , -p , -v , -y "
    echo "                usage   :                         sh $SCRIPT_NAME -m  create_chain <-t  (cert_type) > <-c  (common_name_leaf) > <-n (prefix_common_name) > <-d  (chain-depth) > <-k  (keylength) > <-r  (yes|no)> <-h (Pathlength> <-g | --algorithm (signature algorithm)> <-l | --hash (signature hash algorithm)> <-s  (comma seperated DNS names) > <-p  (comma seperated IPs) > <-y | --startdate (Certificate generation date/valid from> <-v | enddate (Certificate Expiry date/valid to>"
    echo "                "
    echo "       2)  create_root_intermediates              Creates only root and intermediate certificates of given depth"
    echo "                options :                         -k , -d , -r , -n , -h , -g , -l , -v , -y"
    echo "                usage   :                         sh $SCRIPT_NAME -m  create_root_intermediates <-n (prefix_common_name) > <-d  (chain-depth) > <-k  (keylength) > <-r  (yes|no)> <-h (Pathlength> <-g | --algorithm (signature algorithm)> <-l | --hash (signature hash algorithm)> <-y | --startdate (Certificate generation date/valid from> <-v | enddate (Certificate Expiry date/valid to>"
    echo "          "
    echo "       3)  create_cert                            Creates CA signed leaf "
    echo "                options :                         -a, -e, -k , -t , -c , -r , -s , -p  , -g , -l , -y , -v"
    echo "                usage   :                         sh $SCRIPT_NAME -m  create_cert [-a  (ca cert path)] [-e (ca key path)] [-c  (common_name) ]  [-t  (cert_type) ] <-k  (keylength) > <-s  (comma seperated DNS names) > <-p  (comma seperated IPs) > <-g | --algorithm (signature algorithm)> <-l | --hash (signature hash algorithm)> <-y | --startdate (Certificate generation date/valid from> <-v | enddate (Certificate Expiry date/valid to>"
    echo "                "
    echo "       4)  create_selfsigned_servercert           Creates Self signed server certificate"
    echo "                options :                         [-c | --fqdn] , -k  , -g , -l "
    echo "                usage   :                         sh $SCRIPT_NAME -m  create_selfsigned_servercert  [-c  (common_name) ]  <-k  (keylength) > <-g | --algorithm (signature algorithm)> <-l | --hash (signature hash algorithm)>"
    echo "                "
    echo "       5)  create_selfsigned_clientcert           Creates self signed client certificate"
    echo "                options :                         [-u | --upn] , -k  , -g , -l  "
    echo "                usage   :                         sh $SCRIPT_NAME -m  create_selfsigned_clientcert  [-u  (common_name) ]  <-k  (keylength) > <-g | --algorithm (signature algorithm)> <-l | --hash (signature hash algorithm)>"
    echo "                "
    echo "       6)  der_to_pem                             Converts DER certificate to PEM format "
    echo "                options :                         -i , -o"
    echo "                usage   :                         sh $SCRIPT_NAME -m pem_to_der [-i  (pem file path)] [-o  (der file path)] "
    echo "                "
    echo "       7)  revoke_cert                            Revokes given certificate"
    echo "                options :                         -a , -e , -i "
    echo "                usage   :                         sh $SCRIPT_NAME -m revoke_cert [-a (ca cert path)] [-e  (ca key path)] [-i (cert to revoke)]"
    echo "                "
    echo "       8)  generate_csr                           Generate CSR "
    echo "                options :                         -s , -p , -g , -l "
    echo "                usage   :                         sh $SCRIPT_NAME -m  generate_csr  <-s  (comma seperated DNS names) > <-p  (comma seperated IPs) >  <-g | --algorithm (signature algorithm)> <-l | --hash (signature hash algorithm)>"
    echo "                "
    echo "       9)  pem_to_der                             Converts PEM certificate to DER format "
    echo "                options :                         -i , -o"
    echo "                usage   :                         sh $SCRIPT_NAME -m pem_to_der [-i  (pem file path)] [-o  (der file path)] "
    echo "                "
    echo "       10)  generate_crl                           Generates CRL for supplied CA"
    echo "                options :                         -a , -e "
    echo "                usage   :                         sh $SCRIPT_NAME -m generate_crl [-a  (ca cert path)] [-e (ca key path)]"
    echo "                "
    echo "      11)  remove_newline                         Generates a base64 text file with \n"
    echo "                options :                         -i"
    echo "                usage   :                         sh $SCRIPT_NAME -m  remove_newline  [-i | --in (cert path)]"
    echo "                "
    echo "      12)  sign_csr_chain                         Creates root and intermedites of (depth-1) and signs a given CSR"
    echo "                options :                         -d , -k , -n , -h , -r , -i , -g , -l , -v , -y"
    echo "                usage   :                         sh $SCRIPT_NAME -m sign_csr_chain [-i (csr path)] <-d  (chain-depth)> <-r  (yes|no)> <-k  (keylength) > <-h (Pathlength> <-n (prefix_common_name) > <-g | --algorithm (signature algorithm)> <-l | --hash (signature hash algorithm)> <-y | --startdate (Certificate generation date/valid from> <-v | enddate (Certificate Expiry date/valid to>"
    echo "                "
    echo "      13)  sign_csr                               Signs a given CSR by default CA"
    echo "                options :                         -i , -r , -a , -e , -g , -l , -y , -v"
    echo "                usage   :                         sh $SCRIPT_NAME -m  sign_csr  [-i (csr path)] <-r  (yes|no)> <-a | --ca (signing CA)> <-e | --cakey (CA Key)>  <-g | --algorithm (signature algorithm for CA)> <-l | --hash (signature hash algorithm for CA)> <-y | --startdate (Certificate generation date/valid from> <-v | enddate (Certificate Expiry date/valid to>"
    echo "                "
    echo "      14)  view_cert                              View PEM format certificate"
    echo "                options :                         -i "
    echo "                usage   :                         sh $SCRIPT_NAME -m view_cert [-i | --in (cert path)] "
    echo "                "
    echo "      15)  view_csr                               View certificate request"
    echo "                options :                         -i"
    echo "                usage   :                         sh $SCRIPT_NAME -m  view_csr  [-i | --in (csr path)] "
    echo "                "
    echo "      16)  view_crl                               View PEM format CRL"
    echo "                options :                         -i"
    echo "                usage   :                         sh $SCRIPT_NAME -m  view_crl  [-i | --in (csr path)] "
    echo "                "
    echo "      17)  pem_to_pkcs12                          Convert PEM certificate to PKCS12(.p12) format "
    echo "                options :                         -i , -o , -e , -w "
    echo "                usage   :                         sh $SCRIPT_NAME -m pem_to_pkcs12  [-i  (pem file path)] [-o  (pkcs12 file path)] [-e (pem key path)] <-w  (yes|no)>"
    echo "                "
    echo "      18)  pkcs12_to_pem                          Convert PKCS12(.p12) certificate to PEM format "
    echo "                options :                         -i , -o , -w "
    echo "                usage   :                         sh $SCRIPT_NAME -m pkcs12_to_pem  [-i  (pkcs12 file path)] [-o  (pem file path)] <-w  (yes|no)>"
    echo "                "
    echo "      19)  crl_pem_to_pkcs12                      Convert PEM certificate to PKCS12(.p12) format "
    echo "                options :                         -i , -o , -e , -w "
    echo "                usage   :                         sh $SCRIPT_NAME -m pem_to_pkcs12  [-i  (pem file path)] [-o  (pkcs12 file path)] [-e (pem key path)] <-w  (yes|no)>"
    echo "                "
    echo "      20)  crl_pkcs12_to_pem                      Convert PKCS12(.p12) certificate to PEM format "
    echo "                options :                         -i , -o , -w "
    echo "                usage   :                         sh $SCRIPT_NAME -m pkcs12_to_pem  [-i  (pkcs12 file path)] [-o  (pem file path)] <-w  (yes|no)>"
}

list_usage(){
    echo "Usage :  sh $SCRIPT_NAME -m [(FUNCTION_NAME)]  [- | --] <options> "
    echo "          "
    echo "           -k, --keylength                        Key length (Bits) of certificate. Default value : 2048"
    echo "           -d, --chain-depth                      Number of certificates in chain"
    echo "           -t, --cert-type                        Certificate type. Possible values include : server | client | server_client"
    echo "           -r, --retain-ca                        Retains or Create New CA. Possible values : yes | no .Default value: no"
    echo "           -c, --fqdn                             Fully qualified domain name. Appllicable only for cert-type server or server_client"
    echo "           -u, --upn                              User principle name or email Id of client . Applicable for client"
    echo "           -i, --in                               Input file path"
    echo "           -o, --out                              Output file path"
    echo "           -a, --ca                               CA certificate file path"
    echo "           -e, --cakey                            CA key file path"
    echo "           -s, --DNS                              Comma seperated DNS names"
    echo "           -p, --IP                               Comma seperated IP address"
    echo "           -x, --example                          Display sample examples of all functions"
    echo "           -w, --default-password                 use default cert tool password"
    echo "           -n, --CNPrefix                         prefix for Common Name provided to the chain"
    echo "           -g, --algorithm                        Signature algorithm(rsa,ecdsa)"
    echo "           -l, --hash                             Signature hash algorithm(sha256,sha384)"
    echo "           -y, --startdate                        The date of issue of the certificate. Format accepted : yymmddHHMMSS or yyyymmddHHMMSS"
    echo "           -v, --enddate                          The expiry date of the certificate. Format accepted : yymmddHHMMSS or yyyymmddHHMMSS"
    echo "          "
    if [[ $METHOD == "create_chain" ]]; then
        echo "create_chain                           Creates root, intermediates and leaf of given depth"
        echo "     options :                         -d , -k , -r , -n , -h , -g , -l , -t , -c , -s , -p , -y , -v"
        echo "     usage   :                         sh $SCRIPT_NAME -m  create_chain <-t  (cert_type) > <-c  (common_name_leaf) > <-n (prefix_common_name) > <-d  (chain-depth) > <-k  (keylength) > <-r  (yes|no)> <-h (Pathlength> <-g | --algorithm (signature algorithm)> <-l | --hash (signature hash algorithm)> <-s  (comma seperated DNS names) > <-p  (comma seperated IPs) > <-y | --startdate (Certificate generation date/valid from> <-v | enddate (Certificate Expiry date/valid to>"

    elif [[ $METHOD == "create_root_intermediates" ]]; then
        echo "create_root_intermediates              Creates only root and intermediate certificates of given depth"
        echo "     options :                         -k , -d , -r , -n , -h , -g , -l , -y , -v"
        echo "     usage   :                         sh $SCRIPT_NAME -m  create_root_intermediates <-n (prefix_common_name) > <-d  (chain-depth) > <-k  (keylength) > <-r  (yes|no)> <-h (Pathlength> <-g | --algorithm (signature algorithm)> <-l | --hash (signature hash algorithm)> <-y | --startdate (Certificate generation date/valid from> <-v | enddate (Certificate Expiry date/valid to>"

    elif [[ $METHOD == "create_cert" ]]; then
        echo "create_cert                            Creates CA signed leaf "
        echo "     options :                         -a, -e, -k , -t , -c , -r , -s , -p  , -g , -l , -y , -v"
        echo "     usage   :                         sh $SCRIPT_NAME -m  create_cert [-a  (ca cert path)] [-e (ca key path)] [-c  (common_name) ]  [-t  (cert_type) ] <-k  (keylength) > <-s  (comma seperated DNS names) > <-p  (comma seperated IPs) > <-g | --algorithm (signature algorithm)> <-l | --hash (signature hash algorithm)> <-y | --startdate (Certificate generation date/valid from> <-v | enddate (Certificate Expiry date/valid to>"

    elif [[ $METHOD == "create_selfsigned_servercert" ]]; then
        echo "create_selfsigned_servercert           Creates Self signed server certificate"
        echo "     options :                         [-c | --fqdn] , -k  , -g , -l "
        echo "     usage   :                         sh $SCRIPT_NAME -m  create_selfsigned_servercert  [-c  (common_name) ]  <-k  (keylength) > <-g | --algorithm (signature algorithm)> <-l | --hash (signature hash algorithm)>"

    elif [[ $METHOD == "create_selfsigned_clientcert" ]]; then
        echo "create_selfsigned_clientcert           Creates self signed client certificate"
        echo "     options :                         [-u | --upn] , -k  , -g , -l  "
        echo "     usage   :                         sh $SCRIPT_NAME -m  create_selfsigned_clientcert  [-u  (common_name) ]  <-k  (keylength) > <-g | --algorithm (signature algorithm)> <-l | --hash (signature hash algorithm)>"

    elif [[ $METHOD == "der_to_pem" ]]; then
        echo "der_to_pem                             Converts DER certificate to PEM format "
        echo "     options :                         -i , -o"
        echo "     usage   :                         sh $SCRIPT_NAME -m pem_to_der [-i  (pem file path)] [-o  (der file path)] "

    elif [[ $METHOD == "generate_crl" ]]; then
        echo "generate_crl                           Generates CRL for supplied CA"
        echo "    options :                         -a , -e "
        echo "    usage   :                         sh $SCRIPT_NAME -m generate_crl [-a  (ca cert path)] [-e (ca key path)]"
        echo "    "
    elif [[ $METHOD == "generate_csr" ]]; then
        echo "generate_csr                           Generate CSR "
        echo "     options :                         -s , -p , -g , -l "
        echo "     usage   :                         sh $SCRIPT_NAME -m  generate_csr  <-s  (comma seperated DNS names) > <-p  (comma seperated IPs) >  <-g | --algorithm (signature algorithm)> <-l | --hash (signature hash algorithm)>"

    elif [[ $METHOD == "pem_to_der" ]]; then
        echo "pem_to_der                             Converts PEM certificate to DER format "
        echo "     options :                         -i , -o"
        echo "     usage   :                         sh $SCRIPT_NAME -m pem_to_der [-i  (pem file path)] [-o  (der file path)] "

    elif [[ $METHOD == "revoke_cert" ]]; then
        echo "revoke_cert                            Revokes given certificate"
        echo "     options :                         -a , -e , -i "
        echo "     usage   :                         sh $SCRIPT_NAME -m revoke_cert [-a (ca cert path)] [-e  2(ca key path)] [-i (cert to revoke)]"

    elif [[ $METHOD == "remove_newline" ]]; then
        echo "remove_newline                         Generates a base64 text file with \n"
        echo "     options :                         -i"
        echo "     usage   :                         sh $SCRIPT_NAME -m  remove_newline  [-i | --in (cert path)]"

    elif [[ $METHOD == "sign_csr_chain" ]]; then
        echo "sign_csr_chain                         Creates root and intermedites of (depth-1) and signs a given CSR"
        echo "     options :                         -d , -k , -n , -h , -r , -i , -g , -l , -y , -v"
        echo "     usage   :                         sh $SCRIPT_NAME -m sign_csr_chain [-i (csr path)] <-d  (chain-depth)> <-r  (yes|no)> <-k  (keylength) > <-h (Pathlength> <-n (prefix_common_name) > <-g | --algorithm (signature algorithm)> <-l | --hash (signature hash algorithm)> <-y | --startdate (Certificate generation date/valid from> <-v | enddate (Certificate Expiry date/valid to>"

    elif [[ $METHOD == "sign_csr" ]]; then
        echo "sign_csr                               Signs a given CSR by default CA"
        echo "     options :                         -i , -r , -a , -e , -g , -l , -y , -v"
        echo "     usage   :                         sh $SCRIPT_NAME -m  sign_csr  [-i (csr path)] <-r  (yes|no)> <-a | --ca (signing CA)> <-e | --cakey (CA Key)>  <-g | --algorithm (signature algorithm for CA)> <-l | --hash (signature hash algorithm for CA)> <-y | --startdate (Certificate generation date/valid from> <-v | enddate (Certificate Expiry date/valid to>"

    elif [[ $METHOD == "view_cert" ]]; then
        echo "view_cert                              View PEM format certificate"
        echo "     options :                         -i "
        echo "     usage   :                         sh $SCRIPT_NAME -m view_cert [-i | --in (cert path)] "

    elif [[ $METHOD == "view_csr" ]]; then
        echo "view_csr                               View certificate request"
        echo "     options :                         -i"
        echo "     usage   :                         sh $SCRIPT_NAME -m  view_csr  [-i | --in (csr path)] "
    elif [[ $METHOD == "view_crl" ]]; then
        echo "view_crl                               View PEM format CRL"
        echo "     options :                         -i"
        echo "     usage   :                         sh $SCRIPT_NAME -m  view_crl  [-i | --in (csr path)] "
    elif [[ $METHOD == "pem_to_pkcs12" ]]; then
        echo "pem_to_pkcs12                          Convert PEM certificate to PKCS12(.p12) format "
        echo "     options :                         -i , -o , -e , -w "
        echo "     usage   :                         sh $SCRIPT_NAME -m pem_to_pkcs12  [-i  (pem file path)] [-o  (pkcs12 file path)] [-e (pem key path)] <-w  (yes|no)>"

    elif [[ $METHOD == "pkcs12_to_pem" ]]; then
        echo "pkcs12_to_pem                          Convert PKCS12(.p12) certificate to PEM format "
        echo "     options :                         -i , -o , -w "
        echo "     usage   :                         sh $SCRIPT_NAME -m pkcs12_to_pem  [-i  (pkcs12 file path)] [-o  (pem file path)] <-w  (yes|no)>"

    elif [[ $METHOD == "crl_pem_to_der" ]]; then
        echo "crl_pem_to_pkcs12                      Convert PEM certificate to PKCS12(.p12) format "
        echo "     options :                         -i , -o , -e , -w "
        echo "     usage   :                         sh $SCRIPT_NAME -m pem_to_pkcs12  [-i  (pem file path)] [-o  (pkcs12 file path)] [-e (pem key path)] <-w  (yes|no)>"

    elif [[ $METHOD == "crl_der_to_pem" ]]; then
        echo "crl_pkcs12_to_pem                      Convert PKCS12(.p12) certificate to PEM format "
        echo "     options :                         -i , -o , -w "
        echo "     usage   :                         sh $SCRIPT_NAME -m pkcs12_to_pem  [-i  (pkcs12 file path)] [-o  (pem file path)] <-w  (yes|no)>"
    else
        list_available_functions
        echo "          "
    fi
    echo "          "
    echo "For Sample Examples execute : sh $SCRIPT_NAME -x"
}

examples(){
    echo "Examples :"
          echo "create_chain : "
        echo "                    sh $SCRIPT_NAME -m create_chain -r no -d 5 -c leaf.cert.com -t client"
    echo "                    sh $SCRIPT_NAME -m create_chain -r yes -d 5 -c leaf.cert.com -t server -k 2048"
    echo "          "
    echo "create_cert :  "
    echo "                    sh $SCRIPT_NAME -m  create_cert -a C:/Certs/ca.cer -e C:/Certs/ca.key -c  leaf.cert.com   -t  server  -k  2048  "
    echo "                    sh $SCRIPT_NAME -m  create_cert -a C:/Certs/inter.cer -e C:/Certs/inter.key -c  ilo.com   -t  server  -k  2048 -s domain.com, domain1.com -p 192.168.2.2, 172.16.14.2 "
    echo "                    sh $SCRIPT_NAME -m  create_cert -a C:/Certs/ca.cer -e C:/Certs/ca.key -u  prism@hpe.com   -t  client  -k  2048 -p 192.168.2.2, 172.16.14.2 "
    echo "          "
    echo "create_root_intermediates :  "
    echo "                    sh $SCRIPT_NAME -m  create_root_intermediates  -d  2  -k  2048  -r  yes -n Common_Name_prefix_for_full_chain"
    echo "                    sh $SCRIPT_NAME -m  create_root_intermediates  -d  3  -k  2048  -r  no -n Common_Name_prefix_for_full_chain"
    echo "          "
    echo "create_selfsigned_servercert :  "
    echo "                    sh $SCRIPT_NAME -m  create_selfsigned_servercert  -c  prism.hpe.com   -k  1024"
    echo "                    sh $SCRIPT_NAME -m  create_selfsigned_servercert  -c  prismteam.hpe.com"
    echo "          "
    echo "create_selfsigned_clientcert :  "
    echo "                    sh $SCRIPT_NAME -m  create_selfsigned_clientcert  -u  prism@hpe.com   -k  2048"
    echo "          "
    echo "der_to_pem :  "
    echo "                    sh $SCRIPT_NAME -m  der_to_pem  -i C:/Certs/dercert.der  -o C:/Certs/pemCert.cer"
    echo "                    sh $SCRIPT_NAME -m  der_to_pem  -i C:/Certs/dercert.cer  -o C:/Certs/pemCert.cer"
    echo "          "
    echo "generate_crl :  "
    echo "                    sh $SCRIPT_NAME -m  generate_crl  -a  C:/Certs/Ca.cer  -e  C:/Certs/Ca.key "
    echo "          "
    echo "generate_csr :  "
    echo "                    sh $SCRIPT_NAME -m  generate_csr  -s prism.com,prism1.com   -p  192.168.1.1,192.168.1.2   "
    echo "          "
    echo "pem_to_der :  "
    echo "                    sh $SCRIPT_NAME -m  pem_to_der  -i C:/Certs/pemCert.cer  -o C:/Certs/dercert.cer"
    echo "          "
    echo "revoke_cert :  "
    echo "                    sh $SCRIPT_NAME -m  revoke_cert  -a  C:/Certs/Ca.cer   -e  C:/Certs/Ca.key  -i  C:/Certs/CertToRevoke.cer "
    echo "          "
    echo "remove_newline :  "
    echo "                    sh $SCRIPT_NAME -m  remove_newline  -i  C:/Certs/cert.cer "
    echo "          "
    echo " sign_csr_chain : "
    echo "                    sh $SCRIPT_NAME -m sign_csr_chain -d 5 -k 2048 -i ./csr/sample_csr.req -r no "
    echo "                    sh $SCRIPT_NAME -m sign_csr_chain -d 5 -k 2048 -i ./csr/sample_csr.req -r no -n TestHeadRoot"
    echo "sign_csr :   "
    echo "                    sh $SCRIPT_NAME -m  sign_csr  -i  C:/Certs/sample.req  -r no "
    echo "                    sh $SCRIPT_NAME -m  sign_csr  -i  C:/Certs/sample.req  -r no -a  C:/Certs/Ca.cer   -e  C:/Certs/Ca.key"
    echo "          "
    echo "view_cert :  "
    echo "                    sh $SCRIPT_NAME -m  view_cert  -i C:/Certs/Intermediate.cer "
    echo "          "
    echo "view_csr :  "
    echo "                    sh $SCRIPT_NAME -m  view_csr  -i C:/Certs/Intermediate.req "
    echo "          "
    echo "view_crl :  "
    echo "                    sh $SCRIPT_NAME -m  view_crl  -i C:/Certs/crlFile.crl "
    echo "          "
    echo "pem_to_pkcs12:  "
    echo "                    sh $SCRIPT_NAME -m  pem_to_pkcs12  -i C:/Certs/ca.cer -e C:/Certs/ca.key -o C:/Certs/ca_pkcs12.p12 -w yes"
    echo "                    sh $SCRIPT_NAME -m  pem_to_pkcs12  -i C:/Certs/ca.cer -e C:/Certs/ca.key -o C:/Certs/ca_pkcs12.p12 -w no"
    echo "          "
    echo "pkcs12_to_pem:  "
    echo "                    sh $SCRIPT_NAME -m  pkcs12_to_pem  -i C:/Certs/ca_pkcs12.p12 -o C:/Certs/ca.cer -w yes"
    echo "                    sh $SCRIPT_NAME -m  pkcs12_to_pem  -i C:/Certs/ca_pkcs12.p12 -o C:/Certs/ca.cer -w no"
    echo "          "
    echo "crl_pem_to_der :  "
    echo "                    sh $SCRIPT_NAME -m  crl_pem_to_der  -i C:/Certs/pemCert.pem  -o C:/Certs/dercert.der"
    echo "                    sh $SCRIPT_NAME -m  crl_pem_to_der  -i C:/Certs/pemCert.crl  -o C:/Certs/dercert.crl"
    echo "          "
    echo "crl_der_to_pem :  "
    echo "                    sh $SCRIPT_NAME -m  crl_der_to_pem  -i C:/Certs/dercert.der  -o C:/Certs/pemCert.pem"
    echo "                    sh $SCRIPT_NAME -m  crl_der_to_pem  -i C:/Certs/dercert.crl  -o C:/Certs/pemCert.crl"
    echo "          "
}
OPTS=`getopt -o :m:k:d:t:r:c:i:a:e:h:u:ho:xp:s:w:n:g:l:v:y:q: --long verbose,dry-run,help,stack-size:,method:,keylength:,chain-depth:,startdate:,enddate:,fqdn:,cert-type:,retain-ca:,upn:,in:,ca:,cakey:,out:,dns:,ip:,pathlength:,CNPrefix:,algorithm:,hash:,default-password:--mode:--example -n 'parse-options' -- "$@"`

eval set -- "$OPTS"
KEY_LENGTH=2048
ROOT_COMMON_NAME='Root'
METHOD=
CHAIN_DEPTH=1
CERT_TYPE=
RETAIN_CA='no'
FQDN=
UPN=
INPUT_FILE=
CA_CERT_FILE=
CA_KEY_FILE=
LEAF_COMMON_NAME="HP TestHead Leaf"
DNS=
IPS=
DEFAULT_PASSWORD=
OUTPUT_FILE=
PATH_LEN=-2
ALGORITHM='rsa'
HASH='sha256'
PREFIX_CN="HP TestHead"
MODE="LEGACY"
STARTDATE=$(date '+%y%m%d%H%M%S')
ENDDATE=
FLAGVAR=0
LAST_CA_TO_SIGN_CSR=
while true; do
  case "$1" in
    -m | --method ) METHOD="$2"; shift; shift ;;
    -k | --keylength) KEY_LENGTH="$2"; shift; shift ;;
    -d | --chain-depth) CHAIN_DEPTH="$2";FLAGVAR=1;  shift; shift ;;
    -t | --cert-type) CERT_TYPE="$2"; shift; shift ;;
    -r | --retain-ca) RETAIN_CA="$2"; shift; shift ;;
    -c | --fqdn) LEAF_COMMON_NAME="$2"; shift; shift ;;
    -u | --upn) LEAF_COMMON_NAME="$2"; shift; shift ;;
    -i | --in) INPUT_FILE="$2"; shift; shift ;;
    -o | --out) OUTPUT_FILE="$2"; shift; shift ;;
    -a | --ca) CA_CERT_FILE="$2"; shift; shift ;;
    -e | --cakey) CA_KEY_FILE="$2"; shift; shift ;;
    -s | --dns) DNS="$2"; shift; shift ;;
    -p | --ip) IPS="$2"; shift; shift ;;
    -g | --algorithm) ALGORITHM="$2"; shift; shift;;
    -n | --CNPrefix) PREFIX_CN="$2"; shift; shift ;;
    -q | --mode) MODE="$2"; shift; exit ;;
    -h | --pathlength) PATH_LEN="$2"; shift; shift ;;
    -l | --hash) HASH="$2"; shift; shift ;;
    -w | --default-password) DEFAULT_PASSWORD="$2"; shift; shift ;;
    -y | --startdate) STARTDATE="$2"; shift; shift ;;
    -v | --enddate) ENDDATE="$2"; shift; shift ;;
    -h | --help) list_usage; shift; exit ;;
    -x | --example) examples; shift; exit ;;
    --version) echo "cert-tool V1"; shift; exit;;
    * ) break ;;
  esac
done

option=$1
RANDOM=$$

export CRL_URL="$RANDOM"
export PATHLEN='CA:true'
export DIR=.
export FOLDER=.
case $METHOD in

"create_cert") if [[ -z "$LEAF_COMMON_NAME" ]] || [[ -z "$CERT_TYPE" ]] || [[ -z "$KEY_LENGTH" ]] || [[ -z "$CA_CERT_FILE" ]] || [[ -z "$CA_KEY_FILE" ]];then
echo "usage : sh $SCRIPT_NAME -m create_cert [-a | --ca <ca cert path)] [-e | --cakey (ca key path)] [-c  (common_name) ]  [-t | --cert-type (server | client | server_client) ] <-k | --keylength (keylength) > <-s | --dns (comma seperated DNS names) > <-p | --ip (comma seperated IPs) > <-g | --algorithm (signature algorithm)> <-l | --hash (signature hash algorithm)> <-y | --startdate (Certificate generation date/valid from> <-v | enddate (Certificate Expiry date/valid to>"
exit 1;
fi;
create_cert $CA_CERT_FILE $CA_KEY_FILE "$LEAF_COMMON_NAME" $CERT_TYPE $KEY_LENGTH $DNS $IPS;;
"create_selfsigned_servercert") if [[ -z "$LEAF_COMMON_NAME" ]] || [[ -z "$KEY_LENGTH" ]];then
echo "usage : sh $SCRIPT_NAME -m create_selfsigned_servercert [-c | --fqdn (CN or domain name)] <-k | --keylength (keylength)> <-g | --algorithm (signature algorithm)> <-l | --hash (signature hash algorithm)>"
exit 1;
fi;
create_selfsigned_servercert $LEAF_COMMON_NAME $KEY_LENGTH;;
"create_selfsigned_clientcert") if [[ -z "$LEAF_COMMON_NAME" ]] || [[ -z "$KEY_LENGTH" ]];then
echo "usage : sh $SCRIPT_NAME -m create_selfsigned_clientcert [-c | --upn (CN or email id)] <-k | --keylength (keylength)> <-g | --algorithm (signature algorithm)> <-l | --hash (signature hash algorithm)>"
exit 1;
fi;
create_selfsigned_clientcert $LEAF_COMMON_NAME $KEY_LENGTH;;
"sign_csr") if [[ -z "$INPUT_FILE" ]];then
echo "usage : sh $SCRIPT_NAME -m sign_csr [-i | --in (csr path)] <-r | --retain-ca (optional  yes|no)> <-a | --ca (ca cert path)> <-e | --cakey (ca key path)> <-g | --algorithm (signature algorithm for self generated CA)> <-l | --hash (signature hash algorithm for self generated CA)> <-y | --startdate (Certificate generation date/valid from> <-v | enddate (Certificate Expiry date/valid to>"
exit 1;
fi;
sign_csr $INPUT_FILE $RETAIN_CA $CA_CERT_FILE $CA_KEY_FILE;;
"view_cert") if [[ -z "$INPUT_FILE" ]];then
echo "usage : sh $SCRIPT_NAME -m view_cert [-i | --in (cert path)] "
exit 1;
fi;
view_cert $INPUT_FILE;;
"generate_crl") if [[ -z "$CA_CERT_FILE" ]] || [[ -z "$CA_KEY_FILE" ]];then
echo "usage : sh $SCRIPT_NAME -m generate_crl [-a | --ca (ca cert path)] [-e | --cakey (ca key path)] "
exit 1;
fi;
generate_crl $CA_CERT_FILE $CA_KEY_FILE;;
"revoke_cert") if [[ -z "$CA_CERT_FILE" ]] || [[ -z "$CA_KEY_FILE" ]] || [[ -z "$INPUT_FILE" ]];then
echo "usage : sh $SCRIPT_NAME -m revoke_cert [-a | --ca (ca cert path)] [-e | --cakey (ca key path)] [-i | --in (cert to revoke)]"
exit 1;
fi;
revoke_cert $CA_CERT_FILE $CA_KEY_FILE $INPUT_FILE;;
"cert_as_server") if [[ -z "$CA_CERT_FILE" ]] || [[ -z "$CA_KEY_FILE" ]];then
echo "usage : sh $SCRIPT_NAME -m cert_as_server [-a | --ca (ca cert path)] [-e | --cakey (ca key path)] "
exit 1;
fi;
cert_as_server $CA_CERT_FILE $CA_KEY_FILE;;
"cert_as_client") if [[ -z "$CA_CERT_FILE" ]] || [[ -z "$CA_KEY_FILE" ]];then
echo "usage : sh $SCRIPT_NAME -m cert_as_client [-a | --ca (ca cert path)] [-e | --cakey (ca key path)] "
exit 1;
fi;
cert_as_client $CA_CERT_FILE $CA_KEY_FILE;;
"remove_newline") if [[ -z "$INPUT_FILE" ]];then
echo "usage : sh $SCRIPT_NAME -m remove_newline [-i | --in (cert path)] "
exit 1;
fi;
remove_newline '.'  $INPUT_FILE;;
"view_csr") if [[ -z "$INPUT_FILE" ]];then
echo "usage : sh $SCRIPT_NAME -m view_csr [-i | --in (csr path)] "
exit 1;
fi;
view_csr $INPUT_FILE;;
"generate_csr") generate_csr $DNS $IPS;;
"") echo "Use below options"
   list_available_functions
   ;;
"pem_to_der") if [[ -z "$INPUT_FILE" ]] || [[ -z "$OUTPUT_FILE" ]];then
echo "usage : sh $SCRIPT_NAME -m pem_to_der [-i | --in (pem file path)] [-o | --out (der file path)] "
exit 1;
fi;
pem_to_der $INPUT_FILE $OUTPUT_FILE;;
"der_to_pem") if [[ -z "$INPUT_FILE" ]] || [[ -z "$OUTPUT_FILE" ]];then
echo "usage : sh $SCRIPT_NAME -m der_to_pem [-i | --in (der file path)] [-o | --out (pem file path)] "
exit 1;
fi;
der_to_pem $INPUT_FILE $OUTPUT_FILE;;
"crl_pem_to_der") if [[ -z "$INPUT_FILE" ]] || [[ -z "$OUTPUT_FILE" ]];then
echo "usage : sh $SCRIPT_NAME -m crl_pem_to_der [-i | --in (pem file path)] [-o | --out (der file path)] "
exit 1;
fi;
crl_pem_to_der $INPUT_FILE $OUTPUT_FILE;;
"crl_der_to_pem") if [[ -z "$INPUT_FILE" ]] || [[ -z "$OUTPUT_FILE" ]];then
echo "usage : sh $SCRIPT_NAME -m crl_der_to_pem [-i | --in (der file path)] [-o | --out (pem file path)] "
exit 1;
fi;
crl_der_to_pem $INPUT_FILE $OUTPUT_FILE;;
"help")  list_available_functions
   ;;
"create_chain") if [[ -z "$CHAIN_DEPTH" ]] || [[ -z "$KEY_LENGTH" ]] || [[ -z "$LEAF_COMMON_NAME" ]];then
echo "usage : sh $SCRIPT_NAME -m create_chain <-c  (common_name) >  <-t | --cert-type (server | client | server_client) > <-d | --chain-depth (CHAIN_DEPTH) > <-k | --keylength (keylength) > <-r | --retain-ca (optional  yes|no)>  <-n | --CNPrefix (Prefix to Common Name)> <-h | --pathlength (pathlength_for_CA)> <-g | --algorithm (signature_algorithm)> <-s | --dns (comma seperated DNS names) > <-p | --ip (comma seperated IPs) > <-y | --startdate (Certificate generation date/valid from> <-v | enddate (Certificate Expiry date/valid to>"
exit 1;
fi;
if [[ -z $CERT_TYPE ]]; then
    CERT_TYPE="server_client"
fi
if [[ $PREFIX_CN != "HP TestHead" ]]; then
    LEAF_COMMON_NAME="$PREFIX_CN Leaf"
fi
create_chain $CHAIN_DEPTH $KEY_LENGTH "$PREFIX_CN" $PATH_LEN $RETAIN_CA "$LEAF_COMMON_NAME" $CERT_TYPE ;;
"sign_csr_chain") if [[ -z "$CHAIN_DEPTH" ]] || [[ -z "$KEY_LENGTH" ]] || [[ -z "$INPUT_FILE"  ]] ;then
echo "usage : sh $SCRIPT_NAME -m sign_csr_chain [-i | --in (cert path)] <-d | --chain-depth (CHAIN_DEPTH) > <-k | --keylength (keylength) > <-n | --CNPrefix (Prefix to Common Name)> <-h | --pathlength (pathlength_for_CA)> <-g | --algorithm (signature_algorithm)> <-l | --hash (signature hash algorithm)> <-y | --startdate (Certificate generation date/valid from> <-v | enddate (Certificate Expiry date/valid to>"
exit 1;
fi;
sign_csr_chain $CHAIN_DEPTH $KEY_LENGTH "$PREFIX_CN" $PATH_LEN $RETAIN_CA $INPUT_FILE;;
"create_root_intermediates") if [[ -z "$CHAIN_DEPTH" ]] || [[ -z "$KEY_LENGTH" ]];then
echo "usage : sh $SCRIPT_NAME -m create_root_intermediates  <-d | --chain-depth (CHAIN_DEPTH) > <-k | --keylength (keylength) > <-r | --retain-ca (optional  yes|no)>  <-n | --CNPrefix (Prefix to Common Name)> <-h | --pathlength (pathlength_for_CA)> <-g | --algorithm (signature_algorithm)> <-y | --startdate (Certificate generation date/valid from> <-v | enddate (Certificate Expiry date/valid to>"
exit 1;
fi;
create_root_intermediates $CHAIN_DEPTH $KEY_LENGTH "$PREFIX_CN" $PATH_LEN $RETAIN_CA;;
"view_crl") if [[ -z "$INPUT_FILE" ]];then
echo "usage : sh $SCRIPT_NAME -m view_crl [-i | --in (cert path)] "
exit 1;
fi;
view_crl $INPUT_FILE;;
"pem_to_pkcs12") if [[ -z "$INPUT_FILE" ]] || [[ -z "$CA_KEY_FILE" ]] || [[ -z "$OUTPUT_FILE" ]];then
echo "usage : sh $SCRIPT_NAME -m pem_to_pkcs12 [-i  (pem file path)] [-o  (pkcs12 file path)] [-e (pem key path)] <-w  (optional yes|no)> "
exit 1;
fi;
pem_to_pkcs12 $INPUT_FILE $CA_KEY_FILE $OUTPUT_FILE $DEFAULT_PASSWORD;;
"pkcs12_to_pem") if [[ -z "$INPUT_FILE" ]] || [[ -z "$OUTPUT_FILE" ]];then
echo "usage : sh $SCRIPT_NAME -m pkcs12_to_pem [-i  (pkcs12 file path)] [-o  (pem file path)] <-w  (optional yes|no)> "
exit 1
fi;
pkcs12_to_pem $INPUT_FILE $OUTPUT_FILE $DEFAULT_PASSWORD;;
*) echo "Invalid function"
   list_available_functions
   ;;
esac
