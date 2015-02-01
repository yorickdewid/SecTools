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
# src/module/web/joomla.sh                                                     #
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


### JOOMLA WEB MODULE ###


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


# scan for joomla vunerabilities, fingerprint etc. with joomscan
# TOOLS: joomscan
do_joomscan()
{
    opts="-g 'yomama'"

    joomscan ${opts} -u ${URL} 2>&1

    return ${SUCCESS}
}


# go go go
run_audits

# EOF
