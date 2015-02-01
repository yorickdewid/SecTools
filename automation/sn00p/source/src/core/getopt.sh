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
# src/core/getopt.sh                                                           #
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


# get options and set needed flags
get_opts()
{
    while getopts s:f:w:n:o:i:I:x:X:T:cl:m:t:r:vVH flags
    do
        case ${flags} in
            s)
                target_list="${OPTARG}"
                check_host_mode_opts
                ;;
            f)
                logfile="${OPTARG}"
                ;;
            w)
                urls="`echo ${OPTARG} | tr -s ',' ' '`"
                check_web_mode_opts
                ;;
            n)
                net_list="`echo ${OPTARG} | tr -s ',' ' '`"
                check_lan_mode_opts
                ;;
            o)
                mode_opts="${OPTARG}"
                check_mode_opts
                parse_mode_opts
                ;;
            i)
                in_modules="`echo ${OPTARG} | tr -s ',' ' '`"
                ;;
            I)
                in_tools="`echo ${OPTARG} | tr -s ',' ' '`"
                ;;
            x)
                ex_modules="`echo ${OPTARG} | tr -s ',' ' '`"
                ;;
            X)
                ex_tools="`echo ${OPTARG} | tr -s ',' ' '`"
                ;;
            T)
                MOD_TIMEOUT="${OPTARG}"
                ;;
            c)
                check_tools
                ;;
            l)
                list="`echo ${OPTARG} | tr -s ',' ' '`"
                list_audits
                ;;
            m)
                check_make_mod_args "${@}"
                make_module "${@}"
                ;;
            t)
                check_add_audit_args "${@}"
                add_audit "${@}"
                ;;
            r)
                report_style="${OPTARG}"
                check_report_style
                ;;
            v)
                VERBOSE="/dev/stdout"
                ;;
            V)
                echo "${VERSION}"
                exit ${SUCCESS}
                ;;
            H)
                usage
                exit ${SUCCESS}
                ;;
        esac
    done

    return ${SUCCESS}
}


# EOF
