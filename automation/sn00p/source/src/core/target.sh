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
# src/core/target.sh                                                           #
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


# include or exclude given tcp and udp ports from portlist. create a final
# portlist to use for audits
filter_port_list()
{
    tmplist="tmp_ports.lst"

    msg "[*] filtering ports" > ${VERBOSE} 2>&1

    if [ "${in_tcp_mods}" != "NONE" ]
    then
        echo ${in_tcp_mods} | tr -s ' ' '\n' > "${tmplist}"
    fi

    if [ "${ex_tcp_mods}" != "NONE" ]
    then
        grep -v "`echo ${ex_tcp_mods} | tr -s ' ' '\n'`" "${host}/${portlist}" |
        tee ${tmplist} > ${VERBOSE} 2>&1
    fi

    if [ "${in_udp_mods}" != "NONE" ]
    then
        echo ${in_udp_mods} | tr -s ' ' '\n' > "${tmplist}"
    fi

    if [ "${ex_udp_mods}" != "NONE" ]
    then
        grep -v "`echo ${ex_udp_mods} | tr -s ' ' '\n'`" "${host}/${portlist}" \
            > "${tmplist}" > ${VERBOSE} 2>&1
    fi

    # delete lines with default and move to final portlist file
    if [ -f "${tmplist}" ]
    then
        sed '/^default/d' < ${tmplist} > "${host}/${portlist}"
    fi

    return ${SUCCESS}
}


# create a new portlist from nmap logfile
make_nmap_port_list()
{
    parse_nmap_protocol
    portlist="${protocol}_port.lst"
    parse_nmap_ports

    return ${SUCCESS}
}


# create a portlist from command line list
make_target_port_list()
{
    parse_target_protocol
    check_protocol
    portlist="${protocol}_port.lst"
    parse_target_ports

    return ${SUCCESS}
}


# create a new port list from nmap logfile or command line list
make_port_list()
{
    msg "[*] making port list" > ${VERBOSE} 2>&1

    for host in ${hosts}
    do
        if [ ${logfile} ]
        then
            make_nmap_port_list
        else
            make_target_port_list
        fi

        filter_port_list
    done

    return ${SUCCESS}
}


# create a table of list in a temporary file, so we can parse later
# each row's entry and use it for target_list, net_list, etc.
make_table_list()
{
    msg "[*] making target table list" > ${VERBOSE} 2>&1

    list="${1}"
    table_list="table.lst"

    echo ${list} | awk -F ';' '{for (i=1; i<=NF; i++)
    {split($i, a, /:\/*/); print a[1] " " a[2] " " a[3]}}' > ${table_list}

    return ${SUCCESS}
}


# create network interface directories
make_net_dirs()
{
    for netif in ${netifs}
    do
        mkdir ${netif} > ${VERBOSE} 2>&1
    done

    return ${SUCCESS}
}


# create host directories
make_host_dirs()
{
    msg "[*] making host list" > ${VERBOSE} 2>&1

    for host in ${hosts}
    do
        mkdir ${host} > ${VERBOSE} 2>&1
    done

    return ${SUCCESS}
}

# EOF
