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
# src/core/parse.sh                                                            #
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


# tcp or udp ports?
parse_nmap_protocol()
{
    msg "[*] parsing nmap protocol" > ${VERBOSE} 2>&1

    if [ ${usexml} ]
    then
        protocol="`grep "scaninfo" ${logfile} | cut -d '"' -f 4`"
    else
        cnt=`grep "/open/tcp/" ${logfile}  | wc -l`
        if [ ${cnt} -gt 0 ]
        then
            protocol="tcp"
        else
            protocol="udp"
        fi
    fi

    return ${SUCCESS}
}


# parse open ports from nmap grepable-logfile
parse_nmap_grepable_ports()
{
    grep "${host}" ${logfile} | tr -s ',: ' '\n' | grep '/' |
    ${_sed}'s/\/open.*//g;/filtered|closed|\(|\)|\//d' \
        >> "${host}/${portlist}"

    return ${SUCCESS}
}


# parse open ports from nmap xml-logfile
parse_nmap_xml_ports()
{
    # cut relevant xml part to tempfile
    ${_sed} "/<address addr=\"${host}\"/,/<\/host>/wtmp_${host}" \
        ${logfile} > ${VERBOSE} 2>&1

    # get ports from tempfile and write to new file
    awk '/state="open/ {print $3}' "tmp_${host}" |
    tr -d '"><=a-z ' >> "${host}/${portlist}"

    return ${SUCCESS}
}


# parse ports from nmap logfiles
parse_nmap_ports()
{
    msg "[*] parsing nmap ports" > ${VERBOSE} 2>&1

    if [ ${usexml} ]
    then
        parse_nmap_xml_ports
    else
        parse_nmap_grepable_ports
    fi

    return ${SUCCESS}
}


# parse hosts from nmap grepable-logfile
parse_nmap_grepable_hosts()
{
    hosts=`awk '/^Host:/ {print $2}' ${logfile} | uniq`

    return ${SUCCESS}
}


# parse hosts from nmap xml-logfile
parse_nmap_xml_hosts()
{
    hosts="`grep "<address addr=" ${logfile} | cut -d '"' -f 2`"

    return ${SUCCESS}
}


# parse hosts from nmap logfile
parse_nmap_hosts()
{
    msg "[*] parsing nmap hosts" > ${VERBOSE} 2>&1

    if [ ${usexml} ]
    then
        parse_nmap_xml_hosts
    else
        parse_nmap_grepable_hosts
    fi

    return ${SUCCESS}
}


# parse ports from table list
parse_target_ports()
{
    msg "[*] parsing target ports" > ${VERBOSE} 2>&1

    awk '{print $3}' ${table_list} | tr -s ',' '\n' > ${host}/${portlist}

    return ${SUCCESS}
}


# parse network interfaces from list
parse_net_ifs()
{
    netifs="`cut -d ' ' -f 2 ${table_list}`"

    return ${SUCCESS}
}


# parse hosts and ports from host list
parse_target_hosts()
{
    msg "[*] parsing target hosts" > ${VERBOSE} 2>&1

    hosts="`cut -d ' ' -f 2 ${table_list} | tr -d '/'`"

    return ${SUCCESS}
}


# parse protocol value from table list
parse_target_protocol()
{
    msg "[*] parsing target protocol" > ${VERBOSE} 2>&1

    protocol="`grep "${host}" ${table_list} | cut -d ' ' -f 1 | tr -d '\n'`"

    return ${SUCCESS}
}


# parse mode options
parse_mode_opts()
{
    shost="`echo ${mode_opts} | tr -s ';' '\n' | grep '^shost' |
    cut -d '=' -f 2`"
    sport="`echo ${mode_opts} | tr -s ';' '\n' | grep '^sport' |
    cut -d '=' -f 2`"
    smac="`echo ${mode_opts} | tr -s ';' '\n' | grep '^smac' |
    cut -d '=' -f 2`"
    dhost="`echo ${mode_opts} | tr -s ';' '\n' | grep '^dhost' |
    cut -d '=' -f 2`"
    dport="`echo ${mode_opts} | tr -s ';' '\n' | grep '^dport' |
    cut -d '=' -f 2`"
    dmac="`echo ${mode_opts} | tr -s ';' '\n' | grep '^dmac' |
    cut -d '=' -f 2`"
    rhost="`echo ${mode_opts} | tr -s ';' '\n' | grep '^rhost' |
    cut -d '=' -f 2`"
    rport="`echo ${mode_opts} | tr -s ';' '\n' | grep '^rport' |
    cut -d '=' -f 2`"
    rmac="`echo ${mode_opts} | tr -s ';' '\n' | grep '^rmac' |
    cut -d '=' -f 2`"
    ndev="`echo ${mode_opts} | tr -s ';' '\n' | grep '^ndev' | cut -d '=' -f 2`"
    ssid="`echo ${mode_opts} | tr -s ';' '\n' | grep '^ssid' | cut -d '=' -f 2`"
    bssid="`echo ${mode_opts} | tr -s ';' '\n' | grep '^bssid' |
    cut -d '=' -f 2`"
    cookie="`echo ${mode_opts} | tr -s ';' '\n' | grep '^cookie' |
    cut -d '=' -f 2`"
    user="`echo ${mode_opts} | tr -s ';' '\n' | grep '^user' | cut -d '=' -f 2`"
    pass="`echo ${mode_opts} | tr -s ';' '\n' | grep '^pass' | cut -d '=' -f 2`"
    ulists="`echo ${mode_opts} | tr -s ';' '\n' | grep '^ulists' |
    cut -d '=' -f 2 | tr -s ',' ' '`"
    plists="`echo ${mode_opts} | tr -s ';' '\n' | grep '^plists' |
    cut -d '=' -f 2 | tr -s ',' ' '`"

    return ${SUCCESS}
}


# parsing options from sn00p config file
parse_conf()
{
    msg "[*] parsing sn00p.conf" > ${VERBOSE} 2>&1

    if [ -f "${SN00P_PATH}/sn00p.conf" ]
    then
        ndev=`grep "^NETDEV=" ${SN00P_PATH}/sn00p.conf | cut -d '=' -f 2 |
        tr -d '"' | tr -s ',' ' '`
        in_modules=`grep "^IN_MODULES=" ${SN00P_PATH}/sn00p.conf |
        cut -d '=' -f 2 | tr -d '"' | tr -s ',' ' '`
        in_tools=`grep "^IN_TOOLS=" ${SN00P_PATH}/sn00p.conf | cut -d '=' -f 2 |
        tr -d '"' | tr -s ',' ' '`
        ex_modules=`grep "^EX_MODULES=" ${SN00P_PATH}/sn00p.conf |
        cut -d '=' -f 2 | tr -d '"' | tr -s ',' ' '`
        ex_tools=`grep "^EX_TOOLS=" ${SN00P_PATH}/sn00p.conf | cut -d '"' -f 2 |
        tr -d '"' | tr -s ',' ' '`
        user=`grep "^USER=" ${SN00P_PATH}/sn00p.conf | cut -d '"' -f 2 |
        tr -d '"' | tr -s ',' ' '`
        pass=`grep "^PASS=" ${SN00P_PATH}/sn00p.conf | cut -d '"' -f 2 |
        tr -d '"' | tr -s ',' ' '`
        ulists=`grep "^USERLISTS=" ${SN00P_PATH}/sn00p.conf |
        cut -d '"' -f 2 | tr -d '"' | tr -s ',' ' '`
        plists=`grep "^PASSLISTS=" ${SN00P_PATH}/sn00p.conf |
        cut -d '"' -f 2 | tr -d '"' | tr -s ',' ' '`
   else
        error "can't read or find sn00p config file"
    fi

    return ${SUCCESS}
}

# EOF
