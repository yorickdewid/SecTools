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


# <hr>
make_css_line()
{
    echo "#line" >> ${cfile}
    echo "{" >> ${cfile}
    echo "    background-color: red;" >> ${cfile}
    echo "    height: 1px;" >> ${cfile}
    echo "    width: 910px auto;" >> ${cfile}
    echo "}" >> ${cfile}
    echo >> ${cfile}

    return ${SUCCESS}
}


# <table>
make_css_tables()
{
    echo "body table" >> ${cfile}
    echo "{" >> ${cfile}
    echo "    font-size: 12px;" >> ${cfile}
    echo "    font-family: arial;" >> ${cfile}
    echo "    width: 200px;" >> ${cfile}
    echo "}" >> ${cfile}
    echo >> ${cfile}

    return ${SUCCESS}
}


# <a>
make_css_links()
{
    echo "body a" >> ${cfile}
    echo "{" >> ${cfile}
    echo "    color: #d8d8d8;" >> ${cfile}
    echo "    text-decoration: none;" >> ${cfile}
    echo "}" >> ${cfile}
    echo >> ${cfile}
    echo "body a:hover" >> ${cfile}
    echo "{" >> ${cfile}
    echo "    color: #088A08;" >> ${cfile}
    echo "    text-decoration: none;" >> ${cfile}
    echo "}" >> ${cfile}
    echo >> ${cfile}

    return ${SUCCESS}
}


# <body>
make_css_body()
{
    # body part
    echo '@charset "UTF-8";' > ${cfile}
    echo >> ${cfile}
    echo "body" >> ${cfile}
    echo "{" >> ${cfile}
    echo "    font-size: 12px;" >> ${cfile}
    echo "    font-family: arial;" >> ${cfile}
    echo "    width: 910px;" >> ${cfile}
    echo "    color: #40FF00;" >> ${cfile}
    echo "    background-color: #000000;" >> ${cfile}
    echo "}" >> ${cfile}
    echo >> ${cfile}

    return ${SUCCESS}
}


# generate css file for html report
make_css()
{
    make_css_body
    make_css_links
    make_css_tables
    make_css_line

    return ${SUCCESS}
}


# EOF
