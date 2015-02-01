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
# src/core/misc.sh                                                             #
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


# delete temporary created and used files
clean_up()
{
    msg "[*] cleaning up" > ${VERBOSE} 2>&1

    # delete nmap logfile
    if [ -f "${BEGIN_PATH}/${sn00p_dir}/${logfile}" ]
    then
        rm -rf ${BEGIN_PATH}/${sn00p_dir}/${logfile} > ${VERBOSE} 2>&1
    fi

    # delete temp-port list files
    rm -rf ${BEGIN_PATH}/${sn00p_dir}/tmp_* > ${VERBOSE} 2>&1

    # delete port list files
    rm -rf ${BEGIN_PATH}/${sn00p_dir}/*/*_port.lst > ${VERBOSE} 2>&1

    # delete table.lst
    rm -rf ${BEGIN_PATH}/${sn00p_dir}/table.lst > ${VERBOSE} 2>&1

    return ${SUCCESS}
}


# print syntax of arguments for 'add audit' option
print_add_audit_syntax()
{
    echo "[*] syntax:"
    echo "  -> <module> <audit> [cmd] [cmd_args]"
    echo "[*] example:"
    echo "  -> tcp/22.sh crack_ssh sshcracker -c foo -f bar"
    exit ${SUCCESS}

    return ${SUCCESS}
}


# print syntax of arguments for 'create module' option
print_create_mod_syntax()
{
    echo "[*] syntax:"
    echo "  -> <module> <audit> [cmd] [cmd_args]"
    echo "[*] example:"
    echo "  -> tcp/1337.sh ping_flood killahping -s 9999"
    exit ${SUCCESS}

    return ${SUCCESS}
}


# print syntax and options for mode options
print_mode_opts_syntax()
{
    echo "[*] syntax:"
    echo "  -> '[<opt-1>=<value>];...;[opt-N=<value1>,<value2>]'"
    echo "[*] options:"
    echo "  -> shost <host>      - source host"
    echo "  -> sport <port>      - source port"
    echo "  -> smac <macaddr>    - source macaddr"
    echo "  -> dhost <host>      - target host"
    echo "  -> dport <port>      - target port"
    echo "  -> dmac <macaddr>    - target macaddr"
    echo "  -> rhost <host>      - router host"
    echo "  -> rport <port>      - router port"
    echo "  -> rmac <macaddr>    - router macaddr"
    echo "  -> ndev <interface>  - network interface"
    echo "  -> ssid <name>       - wifi ssid"
    echo "  -> bssid <addr>      - wifi bssid"
    echo "  -> cookie <cookies>  - web cookie"
    echo "  -> user <username>   - single username"
    echo "  -> pass <password>   - single password"
    echo "  -> ulists <files>    - username lists"
    echo "  -> plists <files>    - password lists"
    echo "[*] example:"
    echo "  -> 'rhost=192.168.0.1;sport=1337;ndev=em0,"
    echo "      dmac=aa:bb:cc:dd:ee:ff;ssid=nullsex;ulists=/tmp/users.lst;"
    echo "      plists=/home/haxor/pass.lst,pass2.lst'"

    exit ${SUCCESS}

    return ${SUCCESS}
}


# print syntax of arguments for (w)lan mode
print_lan_mode_syntax()
{
    echo "[*] syntax:"
    echo "  -> '<type>://<interface>;...'"
    echo "[*] example:"
    echo "  -> 'lan://eth0;wlan://wlan0'"

    exit ${SUCCESS}

    return ${SUCCESS}
}


# print syntax of arguments for webapp mode
print_web_mode_syntax()
{
    echo "[*] syntax:"
    echo "  -> '<url-1>,...,<url-n>'"
    echo "[*] example:"
    echo "  -> 'http://nullsecurity.net/,http://localhost'"

    exit ${SUCCESS}

    return ${SUCCESS}
}


# print syntax of arguments for host mode
print_host_mode_syntax()
{
    echo "[*] syntax:"
    echo "  -> '<protocol>://<host>:<port-1>,...,<port-n>;...'"
    echo "[*] example:"
    echo "  -> 'udp://nullsecurity.net:514,161;tcp://google.com/'"

    exit ${SUCCESS}

    return ${SUCCESS}
}


# create sn00p dir and change the working dir
make_sn00p_dir()
{
    msg "[*] making sn00p dir" > ${VERBOSE} 2>&1

    mkdir ${sn00p_dir} > ${VERBOSE} 2>&1

    if [ ${logfile} ]
    then
        cp ${logfile} ${sn00p_dir} > ${VERBOSE} 2>&1
        logfile="`basename ${sn00p_dir}/${logfile}`"
    fi

    cd ${sn00p_dir}

    return ${SUCCESS}
}


# very important, leet banner
banner()
{
    msg "--==[ sn00p by noptrix@nullsecurity.net ]==--"

    return ${SUCCESS}
}


# usage and help
usage()
{
    msg "usage:\n"
    msg "  sn00p.sh <modes> [options] | <misc>"
    msg "\nmodes:\n"
    msg "  -s <list>     - target hosts and ports - ? to print syntax"
    msg "  -f <file>     - nmap xml or grepable logfile"
    msg "  -w <urls>     - urls for webapp audits - ? to print syntax"
    msg "  -n <list>     - network type and devices for (w)lan audits"
    msg "                - ? to print syntax"
    msg "\noptions:\n"
    msg "  -o <args>     - extra mode options - ? to print syntax"
    msg "  -i <modules>  - include modules (default: all)"
    msg "  -I <audits>   - include tools and tests (default: all)"
    msg "  -x <modules>  - exclude modules (default: none)"
    msg "  -X <audits>   - exclude tools or tests (default: none)"
    msg "  -T <secs>     - timeout between each module (default: none)"
    msg "  -r <type>     - generate html or text report"
    msg "  -v            - verbose mode (default: quiet)"
    msg "\nmisc:\n"
    msg "  -c            - check for missing tools (recommended)"
    msg "  -l <args>     - print all or specified audits and exit"
    msg "  -m <args>     - create a module - ? to print syntax"
    msg "  -t <args>     - add audit to existing module - ? to print syntax"
    msg "  -H            - print this help"
    msg "  -V            - print version number"
    msg "\nexamples:\n"
    msg "  sn00p.sh -s 'udp://nullsecurity.net:514,161;tcp://google.com:80'"
    msg "  sn00p.sh -f /home/haxor/foo.nmap -w 'http://localhost' -r html"
    msg "  sn00p.sh -f nmap/foo.nmap -i tcp_1337 -I netcat,domain,amap -v"
    msg "  sn00p.sh -n 'lan://eth0' -o 'rhost=192.168.0.1;sport=1337'"
    msg "  sn00p.sh -l tcp_1337,host_zonetransfer,udp"
    msg "  sn00p.sh -m tcp/1337.sh ping_flood killahping -s 9999"
    msg "  sn00p.sh -t tcp/22.sh crack_ssh sshcracker -c arg -f arg"

    return ${SUCCESS}
}


# print line
msg()
{
    echo ${ECHO_OPTS} "${@}"

    return ${SUCCESS}
}


# print warning
warn()
{
    echo ${ECHO_OPTS} "[!] WARNING: ${@}" > /dev/stderr

    return ${SUCCESS}
}


# print error and exit
error()
{
    echo ${ECHO_OPTS} "[-] ERROR: ${@}" > /dev/stderr
    exit ${FAILURE}

    return ${SUCCESS}
}

# EOF
