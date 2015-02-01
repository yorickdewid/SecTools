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
# report.sh                                                                    #
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


# generate html based report
report_html()
{
    msg "[*] generating html based report"

    cfile="report/styles.css"
    hfile="report/index.html"

    make_css
    make_html_header "${hfile}"
    make_html_summary "${hfile}"
    make_html_target_list "${hfile}"
    make_html_footer "${hfile}"
    make_html_target_files
    make_html_results

    return ${SUCCESS}
}


# generate text based report
report_txt()
{
    msg "[*] generating text based report"

    tfile="report/index.txt"

    make_txt_header "${tfile}"
    make_txt_summary "${tfile}"
    make_txt_target_list "${tfile}"
    make_txt_results

    return ${SUCCESS}
}


# count number of hosts, tcp/udp ports, urls, lan and wlan targets
count()
{
    # all host directories
    hosts=`find . -maxdepth 1 -type d \! -name "report" \! -name "." |
    sed 's/\.\///g' | sort -t . -k 1,1n -k 2,2n -k 3,3n -k 4,4n`

    # num of hosts, tcp/udp ports and www hosts
    num_hosts="`echo ${hosts} | wc -w`"
    num_tcp="`find */tcp/* -type d 2>/dev/null | cut -d "/" -f 3 | wc -l`"
    num_udp="`find */udp/* -type d 2>/dev/null | cut -d "/" -f 3 | wc -l`"
    num_www="`find . -mindepth 2 -maxdepth 2 -type d -name "web" | wc -l`"
    num_lan="`find . -mindepth 2 -maxdepth 2 -type d -name "lan" | wc -l`"
    num_wlan="`find . -mindepth 2 -maxdepth 2 -type d -name "wlan" | wc -l`"

    return ${SUCCESS}
}


# generate report
report()
{
    # report creation date
    _date="`date +%F`"

    mkdir "report"
    count

    if [ "${report_style}" = "txt" ]
    then
        report_txt
    elif [ "${report_style}" = "html" ]
    then
        report_html
    else
        rm -rf "report" > ${VERBOSE} 2>&1
        return ${SUCCESS}
    fi

    return ${SUCCESS}
}

# EOF
