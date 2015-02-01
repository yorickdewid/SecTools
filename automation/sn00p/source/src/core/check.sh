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
# src/core/check.sh                                                            #
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


# check too see which tools are missing
# TODO: remove 'wc' usage
check_tools()
{
    echo "[*] checking for missing tools"

    tools="`grep -r '^# TOOLS: ' ${SN00P_PATH} | cut -d ' ' -f 3- |
    tr -s ' ' '\n' | sort -u `"
    paths="`echo ${PATH} | tr -s ':' ' '`"

    for tool in ${tools}
    do
        tool=`echo ${tool} | ${_sed} 's/\.sh|\.pl|\.py|\.rb|\.php//'`
        for path in ${paths}
        do
            t="${t} `find ${path} -iname ${tool} -or -iname "${tool}.sh" \
                -or -iname "${tool}.pl" -or -iname "${tool}.py" -or \
                -iname "${tool}.rb" -or -iname "${tool}.php" 2> /dev/null`"
        done

        t=`echo ${t} | wc -w`

        if [ ${t} -eq 0 ]
        then
            echo "  -> ${tool} not found"
        fi

        t=""
    done

    exit ${SUCCESS}

    return ${SUCCESS}
}


# check syntax for report styles
check_report_style()
{
    if [ ${report_style} != "html" -a ${report_style} != "txt" ]
    then
        error "wrong report style. choose 'html' or 'txt'"
    fi

    return ${SUCCESS}
}


# check syntax for extra mode options
check_mode_opts()
{
    if [ "${mode_opts}" = '?' ]
    then
        print_mode_opts_syntax
    fi

    return ${SUCCESS}
}


# check syntax for (w)lan mode options
check_lan_mode_opts()
{
    if [ "${net_list}" = '?' ]
    then
        print_lan_mode_syntax
    fi

    return ${SUCCESS}
}


# check syntax for web mode options
check_web_mode_opts()
{
    if [ "${urls}" = '?' ]
    then
        print_web_mode_syntax
    fi

    return ${SUCCESS}
}


# check syntax for host mode options
check_host_mode_opts()
{
    if [ "${target_list}" = '?' ]
    then
        print_host_mode_syntax
    fi

    return ${SUCCESS}
}


# check target protocol (tcp, udp)
check_protocol()
{
    msg "[*] checking network protocol" > ${VERBOSE} 2>&1

    if [ "${protocol}" != "tcp" -a "${protocol}" != "udp" ]
    then
        error "unknown protocol"
    fi

    return ${SUCCESS}
}


# check for module directory prefix
check_mod_prefix()
{
    modprefix="host/ tcp/ udp/ web/ lan/ wlan/"

    msg "[*] checking module prefix" > ${VERBOSE} 2>&1

    for mod in ${modprefix}
    do
        if echo "${2}" | grep "${mod}" > /dev/null
        then
            return ${SUCCESS}
        fi
    done

    # module prefix was wrong, exiting ...
    error "wrong module prefix"

    return ${SUCCESS}
}


# check arguments for add_audit()
check_add_audit_args()
{
    if [ ${2} = '?' ]
    then
        print_add_audit_syntax
    fi

    if [ ${#} -lt 3 ]
    then
        echo "[-] ERROR: wrong syntax"
        exit ${FAILURE}
    fi

    check_mod_prefix ${*}

    return ${SUCCESS}
}


# check arguments for make_module()
check_make_mod_args()
{
    if [ ${2} = '?' ]
    then
        print_create_mod_syntax
    fi

    if [ ${#} -lt 3 ]
    then
        echo "[-] ERROR: wrong syntax"
        exit ${FAILURE}
    fi

    check_mod_prefix ${*}

    return ${SUCCESS}
}


# check if sn00p directory already exists
check_sn00p_dir()
{
    # new sn00p directory
    sn00p_dir="sn00p-`date +%F`"

    msg "[*] checking sn00p directory" > ${VERBOSE} 2>&1

    if [ -d ${sn00p_dir} ]
    then
        error "sn00p dir already exists"
    fi

    return ${SUCCESS}
}


# check if file is a valid nmap grepable or xml logfile
check_logfile()
{
    msg "[*] checking for nmap logfile" > ${VERBOSE} 2>&1

    if [ -f ${logfile} ]
    then
        nmap_valid=`head -1 ${logfile} | cut -d " " -f 1-2`

        if [ "${nmap_valid}" = "# Nmap" ]
        then
            nmap_grepable=`head -n 1 ${logfile} | grep "\-oG"`

            if [ -z "${nmap_grepable}" ]
            then
                error "${logfile} is not a grepable nmap logfile"
            fi
        elif [ "${nmap_valid}" = '<?xml version="1.0"?>' ]
        then
            usexml="1"
        else
            error "${logfile} not a nmap logfile"
        fi
    else
        error "${logfile} is not a regular file!"
    fi

    return ${SUCCESS}
}


# check for uid 0 (root)
check_uid()
{
    msg "[*] checking user id" > ${VERBOSE} 2>&1

    if [ `whoami` != "root" ]
    then
        warn "you are not root"
    fi

    return ${SUCCESS}
}


# check command line arguments selected by user
check_args()
{
    msg "[*] checking arguments" > ${VERBOSE} 2>&1

    if [ -z "${logfile}" ]
    then
        if [ -z "${target_list}" ]
        then
            if [ -z "${urls}" ]
            then
                if [ -z "${net_list}" ]
                then
                    error "WTF? mount /dev/brain"
                fi
            fi
        fi
    fi

    return ${SUCCESS}
}


# check argument count
check_argc()
{
    if [ ${#} -lt 2 ]
    then
        error "-H for help and usage"
    fi

    return ${SUCCESS}
}


# checks sed version and sets '-E' or '-r' option for given OS
check_sed_version()
{
    msg "[*] checking sed version" > ${VERBOSE} 2>&1

    sed -h 2> "sedtest.txt"
    sedhead=`head -n 1 "sedtest.txt" | cut -d " " -f 2`

    if [ "${sedhead}" = "invalid" ]
    then
        # GNU sickness
        _sed="sed -r"
    else
        _sed="sed -E"
    fi

    rm -rf "${BEGIN_PATH}/sedtest.txt" > ${VERBOSE} 2>&1

    return ${SUCCESS}
}


# set echo options for given OS
check_echo()
{
    if grep "Debian" "/proc/version" > ${VERBOSE} 2>&1
    then
        ECHO_OPTS=""
    elif grep "Ubuntu" "/proc/version" > ${VERBOSE} 2>&1
    then
        ECHO_OPTS=""
    elif [ `uname` = "SunOS" ]
    then
        ECHO_OPTS=""
    elif [ `uname` = "Darwin" ]
    then
        ECHO_OPTS=""
    else
        ECHO_OPTS="-e"
    fi

    return ${SUCCESS}
}


# check if timeout is installed. if not, unset $_TIMEOUT (see global.h).
check_timeout_cmd()
{
    cmd="`timeout --help 2> /dev/null | grep "^Usage"`"

    msg "[*] checking timeout command" > ${VERBOSE} 2>&1

    if [ -z "${cmd}" ]
    then
        warn "timeout command not found. -T option will be ignored"
        _TIMEOUT=""
        MOD_TIMEOUT=""
    fi

    return ${SUCCESS}
}

# EOF
