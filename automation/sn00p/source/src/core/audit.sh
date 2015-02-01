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
# src/core/audit.sh                                                            #
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


# list all audits
list_audit_all()
{
    for i in `ls host/* tcp/* udp/* web/* lan/*`
    do
        tools=`awk '/^do_[a-zA-Z0-9_()]/ {sub("do_",""); print}' ${i} |
        sed 's/()//'`

        msg "\n[*] ${i}"

        for tool in ${tools}
        do
            echo "  -> ${tool}"
        done
    done

    return ${SUCCESS}
}


# list audits from host, tcp, udp, net or web
list_audit_dir()
{
    for i in `ls ${list}/*`
    do
        tools=`awk '/^do_[a-zA-Z0-9_()]/ {sub("do_",""); print}' ${i} |
        sed 's/()//'`

        msg "\n[*] ${i}"

        for tool in ${tools}
        do
            echo "  -> ${tool}"
        done
    done

    return ${SUCCESS}
}


# list audits from selected modules
list_audit_mod()
{
    list=`echo ${list} | tr ',' ' ' | tr '_' '/'`

    for i in ${list}
    do
        if [ -f "${i}.sh" ]
        then
            tools=`awk '/^do_[a-zA-Z0-9_()]/ {sub("do_",""); print}' \
                "${i}.sh" | sed 's/()//'`

            msg "\n[*] ${i}.sh"

            for tool in ${tools}
            do
                echo "  -> ${tool}"
            done
        else
            error "module ${i}.sh does not exist"
         fi
    done

    return ${SUCCESS}
}


# list available audits from modules
list_audits()
{
    cd "${SN00P_PATH}/src/modules"

    if [ "${list}" = "all" ]
    then
        list_audit_all
    elif [ "${list}" = "host" -o "${list}" = "tcp" -o "${list}" = "udp" \
        -o "${list}" = "web" -o "${list}" = "lan" -o "${list}" = "wlan" ]
    then
        list_audit_dir
    else
        list_audit_mod
    fi

    exit ${SUCCESS}

    return ${SUCCESS}
}


# run tcp or udp based audits
service_audits()
{
    # for status
    i=${num_targets}
    j=${cur_target}

    mkdir "${protocol}" > ${VERBOSE} 2>&1

    # run audits for each port/service
    for port in `cat ${portlist}`
    do
        dport="${port}"

        if [ ! -d ${port} ]
        then
            mkdir "${protocol}/${port}" > ${VERBOSE} 2>&1
        fi

        cd "${protocol}/${port}"

        # run default.sh module first
        msg "[*] auditing ${host}:${port} [${protocol} default.sh]"\
            "(${j}/${i})"
        ${_TIMEOUT} ${MOD_TIMEOUT} \
            sh "${SN00P_PATH}/src/modules/${protocol}/default.sh" \
            "${shost}" "${sport}" "${smac}" "${dhost}" "${dport}" "${dmac}" \
            "${rhost}" "${rport}" "${rmac}" "${ndev}" "${ssid}" "${bssid}" \
            "${url}" "${user}" "${pass}" "${ulists}" "${plists}" \
            "${cookie}" "${in_tools}" "${ex_tools}" "${VERBOSE}"
        echo ""

        # now run specified modules
        if [ -f "${SN00P_PATH}/src/modules/${protocol}/${port}.sh" ]
        then
            msg "[*] auditing ${host}:${port} [${protocol} ${port}.sh]"\
                "(${j}/${i})"
            ${_TIMEOUT} ${MOD_TIMEOUT} \
                sh "${SN00P_PATH}/src/modules/${protocol}/${port}.sh" \
                "${shost}" "${sport}" "${smac}" "${dhost}" "${dport}" \
                "${dmac}" "${rhost}" "${rport}" "${rmac}" "${ndev}" "${ssid}" \
                "${bssid}" "${url}" "${user}" "${pass}" "${ulists}" \
                "${plists}" "${cookie}" "${in_tools}" "${ex_tools}" \
                "${VERBOSE}"
            echo ""
        fi

        # back to target dir
        cd "../../"
    done

    return ${SUCCESS}
}


# user included modules for host tests
user_audits()
{
    # for status
    i=${num_targets}
    j=${cur_target}

    for mod in ${in_mods}
    do
        if echo "${in_mods}" | grep "default" > ${VERBOSE} 2>&1
        then
            # we do not need to run default.sh again - delete 'default'
            in_mods=`echo ${in_mods} | sed 's/default//g'`
            continue
        fi
        if [ -f "${SN00P_PATH}/src/modules/${atype}/${mod}.sh" ]
        then
            if [ ! -d "${mod}" ]
            then
                mkdir ${mod}
            fi

            cd ${mod}

            msg "[*] auditing ${host} [${atype} ${mod}.sh] (${j}/${i})"
            ${_TIMEOUT} ${MOD_TIMEOUT} \
                sh "${SN00P_PATH}/src/modules/${atype}/${mod}.sh" \
                "${shost}" "${sport}" "${smac}" "${dhost}" "${dport}" \
                "${dmac}" "${rhost}" "${rport}" "${rmac}" "${ndev}" "${ssid}" \
                "${bssid}" "${url}" "${user}" "${pass}" "${ulists}" \
                "${plists}" "${cookie}" "${in_tools}" "${ex_tools}" \
                "${VERBOSE}"
            echo ""

            # back to ${atype}/
            cd "../"
        else
            warn "module ${mod} does not exist"
        fi
    done

    return ${SUCCESS}
}


# user did not include modules, so all available modules will be run
all_audits()
{
    # for status
    i=${num_targets}
    j=${cur_target}

    # run audit for each module
    for mod in ${modules}
    do
        # exclude modules if chosen
        if ! echo "${ex_mods}" | grep ${mod} > ${VERBOSE} 2>&1
        then
            if [ ! -d "${mod}" ]
            then
                mkdir ${mod}
            fi

            cd ${mod}

            if [ "${mod}" != "default" ]
            then
                msg "[*] auditing ${host} [${atype} ${mod}.sh] (${j}/${i})"
                ${_TIMEOUT} ${MOD_TIMEOUT} \
                    sh "${SN00P_PATH}/src/modules/${atype}/${mod}.sh" \
                    "${shost}" "${sport}" "${smac}" "${dhost}" "${dport}" \
                    "${dmac}" "${rhost}" "${rport}" "${rmac}" "${ndev}" \
                    "${ssid}" "${bssid}" "${url}" "${user}" "${pass}" \
                    "${ulists}" "${plists}" "${cookie}" "${in_tools}" \
                    "${ex_tools}" "${VERBOSE}"
                echo ""
            fi

            # back to ${atype}/
            cd "../"
        fi
    done

    return ${SUCCESS}
}


# define to include and to exclude modules by given audit type
define_modules()
{
    if [ ${atype} = "host" ]
    then
        in_mods="${in_host_mods}"
        ex_mods="${ex_host_mods}"
    elif [ ${atype} = "web" ]
    then
        in_mods="${in_web_mods}"
        ex_mods="${ex_web_mods}"
    elif [ ${atype} = "lan" ]
    then
        in_mods="${in_lan_mods}"
        ex_mods="${ex_lan_mods}"
    elif [ ${atype} = "wlan" ]
    then
        in_mods="${in_wlan_mods}"
        ex_mods="${ex_wlan_mods}"
    else
        return ${SUCCESS}
    fi

    return ${SUCCESS}
}


# run default audits first and then user or all audits for given audit type
audit()
{
    # for status
    i=${num_targets}
    j=${cur_target}

    # audit type
    atype="${1}"

    # read in all available modules for given audit type
    modules="`ls ${SN00P_PATH}/src/modules/${atype} | sed 's/\.sh//g'`"

    if [ ! -d "${atype}" ]
    then
        mkdir ${atype}
    fi

    if [ ! -d "${atype}/default" ]
    then
        mkdir "${atype}/default"
    fi

    cd "${atype}/default"

    define_modules "${atype}"

    # run default.sh first
    msg "[*] auditing ${target} [${atype} default.sh] (${j}/${i})"
    ${_TIMEOUT} ${MOD_TIMEOUT} \
        sh "${SN00P_PATH}/src/modules/${atype}/default.sh" \
        "${shost}" "${sport}" "${smac}" "${dhost}" "${dport}" "${dmac}" \
        "${rhost}" "${rport}" "${rmac}" "${ndev}" "${ssid}" "${bssid}" \
        "${url}" "${user}" "${pass}" "${ulists}" "${plists}" "${cookie}" \
        "${in_tools}" "${ex_tools}" "${VERBOSE}"
    echo ""

    # back to audit type directory
    cd "../"

    if [ "${in_mods}" != "NONE" ]
    then
        # user chosed modules to include
        user_audits
    else
        all_audits
    fi

    # back to target directory
    cd "../"

    return ${SUCCESS}
}


# run lan / wlan based audits
run_net_audits()
{
    # for stat line
    num_targets="`echo ${urls} | tr -s ' ' '\n' | wc -l`"
    cur_target=0

    echo ""

    # grep network type from table list first
    for netif in ${netifs}
    do
        net_type="`grep "${netif}" ${table_list} | cut -d ' ' -f 1`"
        ndev="${netif}"
        target="${ndev}"
        cur_target=`expr ${cur_target} + 1`

        cd ${target}

        if [ ${net_type} = "lan" ]
        then
            audit "lan"
        elif [ ${net_type} = "wlan" ]
        then
            audit "wlan"
        else
            return ${FAILURE}
        fi

        # back to sn00p log dir
        cd "../"
    done

    return ${SUCCESS}
}


# get http or https port for webapp based audits
get_url_port()
{
    protocol="`echo ${url} | cut -d ':' -f 1`"

    if [ "${protocol}" = "http" ]
    then
        port="80"
    elif [ "${protocol}" = "https" ]
    then
        port="443"
    else
        error "unknown web protocol"
    fi

    return ${SUCCESS}
}


# run webapp based audits
run_web_audits()
{
    # for stat line
    num_targets="`echo ${urls} | tr -s ' ' '\n' | wc -l`"
    cur_target=0

    echo ""

    # get all available web modules
    modules=`ls ${SN00P_PATH}/src/modules/web/ | sed 's/\.sh//g'`

    # run audits for each $url
    for url in ${urls}
    do
        target="${url}"
        cur_target=`expr ${cur_target} + 1`

        # make url to host format and create host directory
        host="`echo ${url} | cut -d '/' -f 3 | tr -d ';,?='`"
        mkdir -p "${host}/web/default/" > ${VERBOSE} 2>&1
        cd ${host}

        # http or https?
        get_url_port

        # run default.sh module first
        audit "web"

        # back to sn00p log dir
        cd "../"
    done

    return ${SUCCESS}
}


# run host audits
run_host_audits()
{
    # for stat line
    num_targets="`echo ${hosts} | tr -s ' ' '\n' | wc -l`"
    cur_target=0

    echo ""

    # run host, tcp and udp based audits
    for host in ${hosts}
    do
        target="${host}"
        dhost="${host}"
        cur_target=`expr ${cur_target} + 1`

        # change to target dir and get service protocol if available
        cd ${host}
        protocol="`ls *_port.lst 2> ${VERBOSE} | cut -d '_' -f 1`"

        # host based audits
        audit "host"

        # protocol / service based audits
        if [ "${protocol}" ]
        then
            service_audits
        fi

        # back to sn00p log dir
        cd "../"
    done

    return ${SUCCESS}
}


# EOF
