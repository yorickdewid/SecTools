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
# src/core/module.sh                                                           #
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


# add audits/tools to existing modules
add_audit()
{
    modfile="${SN00P_PATH}/src/modules/${2}"
    tmpfile="xxx.sh"

    msg "[*] adding audit" > ${VERBOSE} 2>&1

    if [ ! -f ${modfile} ]
    then
        error "${2} does not exist"
    fi

    # delete "# go go go, run_audits and # EOF" lines
    ${_sed} '/(\<run_audits\>$)|(# go go go$)|(# EOF)/d' \
        "${SN00P_PATH}/src/modules/${2}" | sed '$d' > ${tmpfile}

    # add audit here
    echo "# <your comment here>" >> ${tmpfile}
    echo "do_${3}()" >> ${tmpfile}
    echo "{" >> ${tmpfile}
    echo "    ${@} 2>&1" | echo "    `cut -d " " -f 8-`" >> ${tmpfile}
    echo "" >> ${tmpfile}
    echo '    return ${SUCCESS}' >> ${tmpfile}
    echo "}" >> ${tmpfile}
    msg "\n\n# go go go\nrun_audits\n\n# EOF" >> ${tmpfile}

    # move and replace file with original
    mv ${tmpfile} ${modfile} > ${VERBOSE} 2>&1

    msg "[*] added audit ${3} to ${2}"
    exit ${SUCCESS}

    return ${SUCCESS}
}


# create own modules from command line
make_module()
{
    modfile="${SN00P_PATH}/src/modules/${2}"
    mod="`echo ${2} | cut -d '/' -f 1`"
    num_lines="-119"

    msg "[*] creating module" > ${VERBOSE} 2>&1

    if [ -f ${modfile} ]
    then
        error "${2} exists"
    fi

    # copy first ${num_lines} lines from ${mod}/default.sh
    head ${num_lines} "${SN00P_PATH}/src/modules/${mod}/default.sh" |
    ${_sed} 's/DEFAULT/\<NAME\>/;
    s/TCP|UDP|WEB|LAN|WLAN/\<PROTOCOL\>/' > ${modfile}

    # create module here
    echo "# <your comment here>" >> ${modfile}
    echo "do_${3}()" >> ${modfile}
    echo "{" >> ${modfile}
    echo "    ${@} 2>&1" | echo "    `cut -d " " -f 8-`" >> ${modfile}
    echo "" >> ${modfile}
    echo '    return ${SUCCESS}' >> ${modfile}
    echo "}" >> ${modfile}
    msg "\n\n# go go go\nrun_audits\n\n# EOF" >> ${modfile}

    msg "[*] created module ${2}"

    exit ${SUCCESS}

    return ${SUCCESS}
}


# exclude given modules
exclude_module()
{
    ex_host_mods=`echo ${ex_modules} |
    awk '{for (i=1; i<=NF; i++) {split($i, a, /host_/); print a[2];}}'`

    ex_tcp_mods=`echo ${ex_modules} |
    awk '{for (i=1; i<=NF; i++) {split($i, a, /tcp_[^0-9]*/); print a[2];}}'`

    ex_udp_mods=`echo ${ex_modules} |
    awk '{for (i=1; i<=NF; i++) {split($i, a, /udp_[^0-9]*/); print a[2];}}'`

    ex_web_mods=`echo ${ex_modules} |
    awk '{for (i=1; i<=NF; i++) {split($i, a, /web_/); print a[2];}}'`

    ex_lan_mods=`echo ${ex_modules} |
    awk '{for (i=1; i<=NF; i++) {split($i, a, /lan_/); print a[2];}}'`

    ex_wlan_mods=`echo ${ex_modules} |
    awk '{for (i=1; i<=NF; i++) {split($i, a, /wlan_/); print a[2];}}'`

    if [ -z "${ex_host_mods}" ]
    then
        ex_host_mods="NONE"
    fi
    if [ -z "${ex_tcp_mods}" ]
    then
        ex_tcp_mods="NONE"
    fi
    if [ -z "${ex_udp_mods}" ]
    then
        ex_udp_mods="NONE"
    fi
    if [ -z "${ex_web_mods}" ]
    then
        ex_web_mods="NONE"
    fi
    if [ -z "${ex_lan_mods}" ]
    then
        ex_lan_mods="NONE"
    fi
    if [ -z "${ex_wlan_mods}" ]
    then
        ex_wlan_mods="NONE"
    fi

    return ${SUCCESS}
}


# include given modules
# keeping awk code simple (combine with tr), cause too much different
# versions...mawk, gawk, awk...FUCK!
include_module()
{
    in_host_mods=`echo ${in_modules} | tr -s ' ' '\n' | tr -s '_' ' ' |
    awk '$1=="host" {print $2;}'`

    in_tcp_mods=`echo ${in_modules} | tr -s ' ' '\n' | tr -s '_' ' ' |
    awk '$1=="tcp" {print $2;}'`

    in_udp_mods=`echo ${in_modules} | tr -s ' ' '\n' | tr -s '_' ' ' |
    awk '$1=="udp" {print $2;}'`

    in_web_mods=`echo ${in_modules} | tr -s ' ' '\n' | tr -s '_' ' ' |
    awk '$1=="web" {print $2;}'`

    in_lan_mods=`echo ${in_modules} | tr -s ' ' '\n' | tr -s '_' ' ' |
    awk '$1=="lan" {print $2;}'`

    in_wlan_mods=`echo ${in_modules} | tr -s ' ' '\n' | tr -s '_' ' ' |
    awk '$1=="wlan" {print $2;}'`

    if [ -z "${in_host_mods}" ]
    then
        in_host_mods="NONE"
    fi
    if [ -z "${in_tcp_mods}" ]
    then
        in_tcp_mods="NONE"
    fi
    if [ -z "${in_udp_mods}" ]
    then
        in_udp_mods="NONE"
    fi
    if [ -z "${in_web_mods}" ]
    then
        in_web_mods="NONE"
    fi
    if [ -z "${in_lan_mods}" ]
    then
        in_lan_mods="NONE"
    fi
    if [ -z "${in_wlan_mods}" ]
    then
        in_wlan_mods="NONE"
    fi

    return ${SUCCESS}
}

# EOF
