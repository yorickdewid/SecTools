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
# report_txt.sh                                                                #
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


# generate results
make_txt_results()
{
    modes="host tcp udp web lan wlan"


    for i in ${hosts}
    do
        msg "[ RESULTS ]\n" >> "report/${i}.txt"
        msg "-----------------------------------------------------------------"\
"---------------\n" >> "report/${i}.txt"

        for mode in ${modes}
        do
            for j in `ls "${i}/${mode}" 2> /dev/null`
            do
                for k in `ls "${i}/${mode}/${j}/" 2> /dev/null`
                do
                    msg "` msg ${j} \(${mode}\) - ${k} | sed 's/\.log//'`\n" \
                        >> "report/${i}.txt"
                    msg "`cat ${i}/${mode}/${j}/${k}`\n" >> "report/${i}.txt"
                    msg "-----------------------------------------------------"\
"---------------------------\n" >> "report/${i}.txt"
                done
            done
        done
    done

    return ${SUCCESS}
}


# generate target list
make_txt_target_list()
{
    tfile="${1}"

    msg "[ TARGET LIST ]\n" >> ${tfile}

    for i in ${hosts}
    do
        msg "${i}" >> ${tfile}
    done

    msg "\n------------------------------------------------------------------"\
"--------------\n" >> ${tfile}

    return ${SUCCESS}
}


# generate text header
make_txt_header()
{
    tfile="${1}"

    msg "sn00p report (`date +%F`)" > ${tfile}
    msg "------------------------------------------------------------------"\
"--------------\n" >> ${tfile}

    return ${SUCCESS}
}


# generate text summay
make_txt_summary()
{
    tfile="${1}"

    msg "[ SUMMARY ]\n" >> ${tfile}
    msg "HOST\t\t${num_hosts}" >> ${tfile}
    msg "TCP\t\t${num_tcp}" >> ${tfile}
    msg "UDP\t\t${num_udp}" >> ${tfile}
    msg "WWW\t\t${num_www}" >> ${tfile}
    msg "LAN\t\t${num_lan}" >> ${tfile}
    msg "WLAN\t\t${num_wlan}" >> ${tfile}
    msg "" >> ${tfile}
    msg "------------------------------------------------------------------"\
"--------------\n" >> ${tfile}

    return ${SUCCESS}
}

# EOF
