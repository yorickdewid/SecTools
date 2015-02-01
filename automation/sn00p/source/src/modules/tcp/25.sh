#!/bin/sh
################################################################################
#                ____                     _ __                                 #
#     ___  __ __/ / /__ ___ ______ ______(_) /___ __                           #
#    / _ \/ // / / (_-</ -_) __/ // / __/ / __/ // /                           #
#   /_//_/\_,_/_/_/___/\__/\__/\_,_/_/ /_/\__/\_, /                            #
#                                            /___/ nullsecurity team           #
#                                                                              #
# sn00p - automates your toolchain for security tests                          #
#                                                                              #
# FILE                                                                         #
# src/modules/tcp/25.sh                                                        #
#                                                                              #
# DATE                                                                         #
# 09/02/2012                                                                   #
#                                                                              #
# DESCRIPTION                                                                  #
# sn00p is a modular tool written in bourne shell and designed to chain and    #
# automate security tools and tests. It parses target definitions from the     #
# command line and runs corresponding modules afterwards. sn00p can also parse #
# a given nmap logfile for open tcp and udp ports. All results will be logged  #
# in specified directories and a report can subsequently be generated.         #
#                                                                              #
# AUTHOR                                                                       #
# noptrix - http://www.nullsecurity.net/                                       #
#                                                                              #
################################################################################


### SMTP MODULE ###


# module params
SHOST="${1}"
SPORT="${2}"
SMAC="${3}"
DHOST="${4}"
DPORT="${5}"
DMAC="${6}"
RHOST="${7}"
RPORT="${8}"
RMAC="${9}"
NDEV="${10}"
SSID="${11}"
BSSID="${12}"
URL="${13}"
USER="${14}"
PASS="${15}"
ULISTS="${16}"
PLISTS="${17}"
COOKIE="${18}"
IN_AUDITS="${19}"
EX_AUDITS="${20}"
VERBOSE="${21}"

# true / false boolean
FALSE="0"
TRUE="1"

# return values
SUCCESS="1337"
FAILURE="31337"

# grep all available tools and tests from this file
AUDITS="`grep '^do_' ${0} | tr -d '()' | cut -d '_' -f 2-`"


# include/exclude given tools from command line or config file
filter_audits()
{
    if [ ! -z "${IN_AUDITS}" ]
    then
        for inc in ${IN_AUDITS}
        do
            if ! echo ${AUDITS} | grep "\<${inc}\>" > /dev/null 2>&1
            then
                IN_AUDITS="`echo ${IN_AUDITS} | sed "s/\<${inc}\>//g"`"
            fi
        done

        AUDITS="${IN_AUDITS}"
    fi

    if [ ! -z "${EX_AUDITS}" ]
    then
        for exc in ${EX_AUDITS}
        do
            AUDITS="`echo ${AUDITS} | sed "s/\<${exc}\>//g"`"
        done
    fi

    # needed for stat line
    num_audits="`echo ${AUDITS} | wc -w | tr -d ' '`"

    return ${SUCCESS}
}


# start all tools here - you do not need to change anything here
run_audits()
{
    j="0"

    filter_audits

    for audit in ${AUDITS}
    do
        j="`expr ${j} + 1`"
        echo "  -> running ${audit} (${j}/${num_audits})"
        do_${audit} 2>&1 | tee -a "${audit}.log" > ${VERBOSE} 2>&1
    done

    return ${SUCCESS}
}


####################### DEFINE AND ADD YOUR STUFF HERE! #######################


# module globals
domain="`head -1 ../../host/default/domain.log 2> /dev/null`"
user1="root"
user2="sn00p"


# check if user enumeration is possible via VRFY using smtp-user-enum
# TOOLS: smtp-user-enum
do_vrfy_scan()
{
    opts1="-v -M VRFY -u root -f localhost"
    opts2="-v -M VRFY -u root -f localhost -D ${domain}"

    if [ -z "${DPORT}" ]
    then
        DPORT="25"
    fi

    # first try user guessing (without domain
    smtp-user-enum ${opts1} -p ${DPORT} -t ${DHOST} 2>&1

    # try email addr guessing
    smtp-user-enum ${opts2} -p ${DPORT} -t ${DHOST} 2>&1

    return ${SUCCESS}
}


# check for existing users via RCPT TO using smtp-user-enum
# TOOLS: smtp-user-enum
do_rcpt_scan()
{
    opts1="-v -M RCPT -u root -f localhost"
    opts2="-v -M RCPT -u root -f localhost -D ${domain}"

    if [ -z "${DPORT}" ]
    then
        DPORT="25"
    fi

    # first try user guessing (without domain
    smtp-user-enum ${opts1} -p ${DPORT} -t ${DHOST} 2>&1

    # try email addr guessing
    smtp-user-enum ${opts2} -p ${DPORT} -t ${DHOST} 2>&1


    return ${SUCCESS}
}


# check for existing users via EXPN using smtp-user-enum
# TOOLS: smtp-user-enum
do_expn_scan()
{
    opts1="-v -M EXPN -u root -f localhost"
    opts2="-v -M EXPN -u root -f localhost -D ${domain}"

    if [ -z "${DPORT}" ]
    then
        DPORT="25"
    fi

    # first try user guessing (without domain
    smtp-user-enum ${opts1} -p ${DPORT} -t ${DHOST} 2>&1

    # try email addr guessing
    smtp-user-enum ${opts2} -p ${DPORT} -t ${DHOST} 2>&1

    return ${SUCCESS}
}


# check for open relay
# TOOLS: ncat
do_open_relay()
{
    ehlo="mail.google.com"
    sender="<root@cia.gov>"
    reciever="<billy@microsoft.com>"

    echo -e "ehlo ${ehlo}\r\nmail from: ${sender}\r\nrcpt to: ${reciever}\r\n"\
    "data\r\nfoobar\r\n." | ncat -v -w 3 ${DHOST} ${DPORT} 2>&1

    return ${SUCCESS}
}


# fingerprint server via smtpscan
# TOOLS: smtpscan
do_smtpscan()
{
    # smtpscan options
    fprint_file="/usr/share/smtpscan/fingerprints"
    test_file="/usr/share/smtpscan/tests"

    smtpscan -f ${fprint_file} -t ${test_file} -p ${DPORT} ${DHOST} 2>&1

    return ${SUCCESS}
}


# bruteforce default logins via hydra
# TOOLS: hydra
do_hydra_smtp()
{
    opts="-e nsr -f -v"

    for i in ${ULISTS}
    do
        for j in ${PLISTS}
        do
            hydra ${opts} -L ${i} -P ${j} smtp://${DHOST}:${DPORT} 2>&1
        done
    done

    return ${SUCCESS}
}


# go go go
run_audits

# EOF
