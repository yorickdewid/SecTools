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
# src/modules/host/default.sh                                                  #
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


### DEFAULT HOST MODULE ###


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


# check, if ${DHOST} is a hostname
check_hostname()
{
    # enough for testing, since ip address don't include a-z or A-Z
    if echo ${DHOST} | grep "[a-zA-Z]" > ${VERBOSE} 2>&1
    then
        hostname="${TRUE}"
    fi

    return ${SUCCESS}
}


# get ipv4 address directly via ${DHOST} or via dns request for A record
# TOOLS: host
do_ipv4addr()
{
    if [ ${hostname} ]
    then
        host -t A ${DHOST} 2>&1 | awk '{print $(NF)}'
    else
        echo "${DHOST}" 2>&1
    fi

    return ${SUCCESS}
}


# get ipv6 address directly via ${DHOST} or via dns request for AAAA record
# TOOLS: host
do_ipv6addr()
{
    if [ ${hostname} ]
    then
        host -t AAAA ${DHOST} 2>&1 | awk '/IPv6 address/ {print $5}'
    else
        echo "${DHOST}" 2>&1
    fi

    return ${SUCCESS}
}


# get hostname directly via ${DHOST} or via dns request for PTR record
# TOOLS: host
do_hostname()
{
    if [ ${hostname} ]
    then
        echo "${DHOST}" 2>&1
    else
        host -t PTR ${DHOST} 2>&1 |
        awk '/pointer/ {sub(/[.]$/, ""); print $(NF)}'
    fi

    return ${SUCCESS}
}


# get domainname directly via ${DHOST} or via dns request for PTR record
# TOOLS: host
do_domain()
{
    domain="`echo ${DHOST} | awk -F'.' '{print $(NF)}'`"

    if [ ! -z "${domain}" ]
    then
        echo "${DHOST}" 2>&1
    else
        host -t PTR ${DHOST} 2>&1 |
        awk '/pointer/ {num=split($0, a, "."); print a[num-2] "." a[num-1]}'
    fi

    return ${SUCCESS}
}


# get ip address range
# TOOLS: whois
do_iprange()
{
    if [ ${hostname} ]
    then
        whois `head -1 ipv4addr.log` 2>&1 |
        awk '/inetnum|NetRange/ {print $2"-"$4}' | head -1
    else
        whois ${DHOST} 2>&1 | awk '/inetnum|NetRange/ {print $2"-"$4}' |
        head -1
    fi

    return ${SUCCESS}
}


# get nameservers (ns records)
# TOOLS: host
do_nameserver()
{
    host -t NS `head -1 domain.log` 2>&1 |
    awk '/name server/ {sub(/[.]$/, ""); print $(NF)}'

    return ${SUCCESS}
}


# get mailserver (mx records)
# TOOLS: host
do_mailserver()
{
    if [ ${hostname} ]
    then
        # try via hostname
        host -t MX `head -1 hostname.log` 2>&1 |
        awk '/is handled/ {sub(/[.]$/, ""); print $(NF)}'
    else
        # try via ipv4 address
        host -t MX `head -1 ipv4addr.log` 2>&1 |
        awk '/is handled/ {sub(/[.]$/, ""); print $(NF)}'
    fi

    # try via domain
    host -t MX `head -n 1 domain.log` 2>&1 |
    awk '/is handled/ {sub(/[.]$/, ""); print $(NF)}'

    return ${SUCCESS}
}


# check for hostname/ipaddr first
check_hostname

# go go go
run_audits

# EOF
