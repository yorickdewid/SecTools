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
# src/core/global.sh                                                           #
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


# sn00p.sh started path
BEGIN_PATH="`pwd`"

# sn00p version string
VERSION="sn00p v0.8"

# true / false boolean
FALSE="0"
TRUE="1"

# return (exit) codes
SUCCESS="1337"
FAILURE="31337"

# verbose mode - default quiet
VERBOSE="/dev/null"

# echo options
ECHO_OPTS=""

# timeout command
_TIMEOUT="timeout"

# default timeout in seconds between each module
MOD_TIMEOUT="0"

# leet color codes
BLUE="\033[94m"
RED="\033[91m"
GREEN="\033[92m"
YELLOW="\033[93m"
NORM="\033[0m"

# EOF
