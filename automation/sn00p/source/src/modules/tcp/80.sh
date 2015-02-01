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
# src/modules/tcp/80.sh                                                        #
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


### HTTP MODULE ###


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


# http header stuff
domain="`head -1 ../../host/default/domain.log 2> /dev/null`"
ua="User-Agent: sn00p.sh"
ref="Referrer: http://www.sn00p.sh/"
clen="Content-Length: -1"


# send HEAD request
# TOOLS: ncat
do_http_head()
{
    # 1.0
    echo -e "HEAD / HTTP/1.0\r\n\n" | ncat -v -w 3 ${DHOST} ${DPORT} 2>&1

    # force new line
    echo ""

    # 1.1
    echo -e "HEAD / HTTP/1.1\nHOST:${domain}\n${ua}\n${ref}\n${clen}\r\n\n" |
    ncat -v -w 3 ${DHOST} ${DPORT} 2>&1

    return ${SUCCESS}
}


# send GET request
# TOOLS: ncat
do_http_get()
{
    # 1.0
    echo -e "GET / HTTP/1.0\r\n\n" | ncat -v -w 3 ${DHOST} ${DPORT} 2>&1

    # force new line
    echo ""

    # 1.1
    echo -e "GET / HTTP/1.1\nHOST:${domain}\n${ua}\n${ref}\n${clen}\r\n\n" |
    ncat -v -w 3 ${DHOST} ${DPORT} 2>&1

    return ${SUCCESS}
}

# send POST request
# TOOLS: ncat
do_http_post()
{
    # 1.0
    echo -e "POST / HTTP/1.0\r\n\n" | ncat -v -w 3 ${DHOST} ${DPORT} 2>&1

    # force new line
    echo ""

    # 1.1
    echo -e "POST / HTTP/1.1\nHOST:${domain}\n${ua}\n${ref}\n${clen}\r\n\n" |
    ncat -v -w 3 ${DHOST} ${DPORT} 2>&1

    return ${SUCCESS}
}


# send OPTIONS request
# TOOLS: ncat
do_http_options()
{
    # 1.0
    echo -e "OPTIONS / HTTP/1.0\r\n\n" | ncat -v -w 3 ${DHOST} ${DPORT} 2>&1

    # force new line
    echo ""

    # 1.1
    echo -e "OPTIONS / HTTP/1.1\nHOST:${domain}\n${ua}\n${ref}\n${clen}\r\n\n" |
    ncat -v -w 3 ${DHOST} ${DPORT} 2>&1

    return ${SUCCESS}
}


# run httping
# TOOLS: httping
do_http_httping()
{
    opts="-a -t 3 -c 2 -I sn00p.sh -R http://sn00p.sh/"

    httping ${opts} -p ${DPORT} -h ${DHOST} 2>&1

    return ${SUCCESS}
}


# fingerprint server via httprint
# TOOLS: httprint
do_http_httprint()
{
    opts="-P0 -th 16"
    sigs="/usr/share/httprint/signatures.txt"

    httprint -h "http://${DHOST}:${DPORT}" -s ${sigs} ${opts} 2>&1

    return ${SUCCESS}
}


# try to get infos over rpc endpoint mapper via rpcdump.py
# TOOLS: rpcdump.py
do_http_rpcdump()
{
    rpcdump.py ${DHOST} "80/HTTP" 2>&1

    return ${SUCCESS}
}


# crawl website via nikto
# TOOLS: nikto.sh
do_http_nikto()
{
    opts="-C all -no404"

    nikto.sh ${opts} -p ${DPORT} -h ${DHOST} 2>&1

    return ${SUCCESS}
}


# go go go
run_audits

# EOF
