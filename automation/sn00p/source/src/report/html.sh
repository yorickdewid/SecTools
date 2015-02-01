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
# report_html.sh                                                               #
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


# generate html header
make_html_header()
{
    hfile="${1}"

    msg "<html>" > ${hfile}
    msg "<head>" >> ${hfile}
    msg "<title>sn00p report</title>" >> ${hfile}
    msg '<link href="styles.css" rel="stylesheet" type="text/css" />' \
        >> ${hfile}
    msg "</head>" >> ${hfile}
    msg "<body>" >> ${hfile}
    msg '<div id="body">' >> ${hfile}
    msg "<h1>sn00p report (`date +%F`)</h1>" >> ${hfile}
    msg '<div id="line"></div>' >> ${hfile}

    return ${SUCCESS}
}


# generate summary
make_html_summary()
{
    msg "<h3>SUMMARY</h3>" >> ${1}
    msg "<table>" >> ${1}
    msg "<tr>" >> ${1}
    msg "<td>HOST</td>" >> ${1}
    msg "<td><a>${num_hosts}</a></td>" >> ${1}
    msg "</tr>" >> ${1}
    msg "<tr>" >> ${1}
    msg "<td>TCP</td>" >> ${1}
    msg "<td><a>${num_tcp}</a></td>" >> ${1}
    msg "</tr>" >> ${1}
    msg "<tr>" >> ${1}
    msg "<td>UDP</td>" >> ${1}
    msg "<td><a>${num_udp}</a></td>" >> ${1}
    msg "</tr>" >> ${1}
    msg "<tr>" >> ${1}
    msg "<td>WWW</td>" >> ${1}
    msg "<td><a>${num_www}</a></td>" >> ${1}
    msg "</tr>" >> ${1}
    msg "<tr>" >> ${1}
    msg "<td>LAN</td>" >> ${1}
    msg "<td><a>${num_lan}</a></td>" >> ${1}
    msg "</tr>" >> ${1}
    msg "<tr>" >> ${1}
    msg "<td>WLAN</td>" >> ${1}
    msg "<td><a>${num_wlan}</a></td>" >> ${1}
    msg "</tr>" >> ${1}
    msg "</table>" >> ${1}
    msg "<br />" >> ${1}
    msg '<div id="line"></div>' >> ${1}

    return ${SUCCESS}
}


# generate target list
make_html_target_list()
{
    # for table rows
    cnt="0"

    msg "<h3>TARGET LIST</h3>" >> ${1}

    for i in ${hosts}
    do
        cnt=`expr ${cnt} + 1`

        # install link
        msg "[ <a href=\"${i}.html\">${i}</a> ]&nbsp;&nbsp;" >> ${1}

        # max 8 rows for table
        if [ ${cnt} -eq 8 ]
        then
            msg "<br />" >> ${1}
            cnt="0"
        fi
    done

    return ${SUCCESS}
}


# generate html files for each host and generate the header
make_html_target_files()
{
    for h in ${hosts}
    do
        make_html_header "report/${h}.html"
    done

    return ${SUCCESS}
}


# results of tcp or udp based audits
make_port_results()
{
    for j in `ls "${i}/${_prot}" 2> /dev/null`
    do
        for k in `ls "${i}/${_prot}/${j}" 2> /dev/null`
        do
            msg "[ <a name=\"${j}\">` msg ${j} - ${k} |
            sed 's/\.log//'`</a> ]<br />" >> ${1}
            msg "<pre>`cat "${i}/${_prot}/${j}/${k}" | sed 's/<//g' |
            sed 's/>//g'`</pre>" >> ${1}
        done
    done

    return ${SUCCESS}
}


# generate results of each hosts from the list
make_html_results()
{
    modes="host tcp udp web lan wlan"

    for i in ${hosts}
    do
        msg "<h3>RESULTS</h3>" >> "report/${i}.html"
        make_modules_links "report/${i}.html"
        msg "<br /><br />" >> "report/${i}.html"
        for mode in ${modes}
        do
            for j in `ls "${i}/${mode}" 2> /dev/null`
            do
                for k in `ls "${i}/${mode}/${j}/" 2> /dev/null`
                do
                    msg "[ <a name=\"${j}\">` msg ${j} - ${k} |
                    sed 's/\.log//'`</a> ]<br />" >> "report/${i}.html"
                    msg "<pre>`cat "${i}/${mode}/${j}/${k}" |
                    sed 's/</\\</g'`</pre>" >> "report/${i}.html"
                done
            done
        done
        msg "<br />" >> "report/${i}.html"
        make_html_footer "report/${i}.html"
        msg '<div id="line"></div>' >> "report/${i}.html"
    done

    return ${SUCCESS}
}


# create links of lan modules in table format
make_lan_links()
{
    msg "LAN<br /><br />" >> ${1}

    for l in `ls "${i}/lan/"`
    do
        if [ ${l} ]
        then
            msg "[ <a href=\"#${l}\">${l}</a> ]&nbsp;&nbsp;" >> ${1}
        fi
    done

    return ${SUCCESS}
}


# create links of web modules in table format
make_web_links()
{
    msg "WWW<br /><br />" >> ${1}

    for w in `ls "${i}/web/" 2> /dev/null`
    do
        if [ ${w} ]
        then
            msg "[ <a href=\"#${w}\">${w}</a> ]&nbsp;&nbsp;" >> ${1}
        fi
    done

    return ${SUCCESS}
}


# create links of ports in table format
make_port_links()
{
    msg "<br /><br />${__prot}<br /><br />" >> ${1}

    for j in `ls "${i}/${_prot}/"`
    do
        msg "[ <a href=\"#${j}\">${j}</a> ]&nbsp;&nbsp;" >> ${1}
    done

    return ${SUCCESS}
}


# create links of hosts in table format
make_host_links()
{
    msg "HOST<br /><br />" >> ${1}

    for j in `ls "${i}/host/" 2> /dev/null`
    do
        if [ ${j} ]
        then
            msg "[ <a href=\"#${j}\">${j}</a> ]&nbsp;&nbsp;" >> ${1}
        fi
    done

    msg "<br /><br />" >> ${1}

    return ${SUCCESS}
}


# create links of modules in table format using div
make_modules_links()
{
    msg "<div style=\"border:1px white solid; height:auto; padding:5px;\">" \
        >> ${1}
    msg "<a name=\"${i}\"><b>${i}</b></a><br /><br />" >> ${1}

    if [ ${num_hosts} -gt 0 ]
    then
        make_host_links ${1}
    fi
    if [ ${num_tcp} -gt 0 ]
    then
        _prot="tcp"
        __prot="TCP"
    fi
    if [ ${num_udp} -gt 0 ]
    then
        _prot="udp"
        __prot="UDP"
    fi
    if [ ${_prot} ]
    then
        if [ ${num_tcp} -gt 0 -o ${num_udp} -gt 0 ]
        then
            make_port_links ${1}
        fi
    else
        _prot="tcp"
    fi
    if [ ${num_www} -gt 0 ]
    then
        make_web_links ${1}
    fi

    msg "<br />" >> ${1}
    msg "</div>" >> ${1}

    return ${SUCCESS}
}


# generate html footer
make_html_footer()
{
    msg "</div>" >> ${1}
    msg "</body>" >> ${1}
    msg "</html>" >> ${1}

    return ${SUCCESS}
}

# EOF
