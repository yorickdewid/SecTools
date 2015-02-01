#!/usr/bin/env python
# -*- coding: latin-1 -*- ######################################################
#                ____                     _ __                                 #
#     ___  __ __/ / /__ ___ ______ ______(_) /___ __                           #
#    / _ \/ // / / (_-</ -_) __/ // / __/ / __/ // /                           #
#   /_//_/\_,_/_/_/___/\__/\__/\_,_/_/ /_/\__/\_, /                            #
#                                            /___/ team                        #
#                                                                              #
# dnsspider.py - multithreaded subdomain bruteforcer                           #
#                                                                              #
# DATE                                                                         #
# 08/16/2012                                                                   #
#                                                                              #
# DESCRIPTION                                                                  #
# A very fast multithreaded bruteforcer of subdomains that leverages a         #
# wordlist and/or character permutation.                                       #
#                                                                              #
# AUTHOR                                                                       #
# noptrix - http://www.nullsecurity.net/                                       #
#                                                                              #
# NOTES:                                                                       #
# quick'n'dirty code                                                           #
#                                                                              #
# CHANGELOG:                                                                   #
# v0.5                                                                         #
# - fixed extracted ip addresses from rrset answers                            #
# - renamed file (removed version string)                                      #
# - removed trailing whitespaces                                               #
# - removed color output                                                       #
# - changed banner                                                             #
#                                                                              #
# v0.4                                                                         #
# - fixed a bug for returned list                                              #
# - added postfix option                                                       #
# - upgraded wordlist[]                                                        #
# - colorised output                                                           #
# - changed error messages                                                     #
#                                                                              #
# v0.3:                                                                        #
# - added verbose/quiet mode - default is quiet now                            #
# - fixed try/catch for domainnames                                            #
# - fixed some tab width (i normally use <= 80 chars per line)                 #
#                                                                              #
# v0.2:                                                                        #
# - append DNS and IP output to found list                                     #
# - added diffound list for subdomains resolved to different addresses         #
# - get right ip address from current used iface to avoid socket problems      #
# - fixed socket exception syntax and output                                   #
# - added usage note for fixed port and multithreaded socket exception         #
#                                                                              #
# v0.1:                                                                        #
# - initial release                                                            #
################################################################################


import sys
import time
import string
import itertools
import socket
import threading
import re


BANNER = '--==[ dnsspider by - noptrix@nullsecurity.net ]==--'
USAGE = '\n\n' \
        '  dnsspider.py -t <arg> -a <arg> [options]'
VERSION = 'dnsspider.py v0.5'

defaults = {}
hostnames = []
prefix = ''
postfix = ''
found = []
diffound = []
chars = string.ascii_lowercase
digits = string.digits

# hostnames
wordlist = [
    'access', 'accounting', 'accounts', 'adm', 'admin',
    'administrator', 'apache', 'app', 'application', 'auth', 'auto', 'backup',
    'backups', 'beta', 'bill', 'billing', 'bm', 'board', 'cart', 'central',
    'chat', 'cli', 'client', 'connect', 'control', 'controller', 'customer',
    'cvs', 'data', 'db', 'demo', 'dev', 'devel', 'developer', 'dns', 'doc',
    'docs', 'document', 'domain', 'download', 'downloads', 'eaccess', 'earth',
    'email', 'example', 'examples', 'exit', 'ext', 'extern', 'external',
    'extranet', 'files', 'finance', 'firewall', 'forum', 'ftp', 'fw', 'gallery',
    'gate', 'gateway', 'git', 'groups', 'guest', 'gw', 'help', 'helpdesk',
    'home', 'hpc', 'image', 'images', 'imap', 'img', 'imgs', 'in', 'info',
    'int', 'interface', 'intern', 'internal', 'intranet', 'ip6', 'ipv6', 'irc',
    'isa', 'it', 'jabber', 'jboss', 'jupiter', 'lan', 'ldap', 'linux', 'login',
    'mail', 'mailgate', 'main', 'manage', 'manager', 'managers', 'marketing',
    'mars', 'mobile', 'mssql', 'mx', 'mx01', 'mysql', 'netmail', 'news', 'noc',
    'ns', 'ns01', 'ns1', 'ntp', 'office', 'online', 'op', 'oracle', 'out',
    'owa', 'partner', 'partners', 'pc', 'personal', 'phpmyadmin', 'plesk',
    'pma', 'pop', 'pop3', 'portal', 'pre', 'printer', 'priv', 'private',
    'proxy', 'pub', 'public', 'rack', 'release', 'report', 'reports',
    'research', 'router', 'sales', 'search', 'sec', 'secure', 'server',
    'services', 'share', 'sharepoint', 'shares', 'shop', 'sms', 'smtp',
    'software', 'sql', 'squirrel', 'squirrelmail', 'srv', 'ssh', 'staff',
    'stage1', 'staging', 'stat', 'static', 'stats', 'storage', 'store',
    'subversion', 'sun', 'support', 'svn', 'test', 'testing', 'tests', 'time',
    'tool', 'tools', 'tunnel', 'unix', 'update', 'upload', 'uploads', 'venus',
    'videos', 'virtual', 'vpn', 'vz', 'wap', 'web', 'webcam', 'webmail',
    'webmin', 'webserver', 'webshop', 'win', 'windows', 'wlan', 'workstation',
    'www', 'www01', 'www1', 'zeus'
]

from optparse import OptionParser
try:
    import dns.message
    import dns.query
except ImportError:
    print("[-] ERROR: you need 'dnspython' package")
    sys.exit()


def usage():
    print('\n' + USAGE)
    sys.exit()
    return


def check_usage():
    if len(sys.argv) == 1:
        print('[-] WARNING: use -h for help and usage')
        sys.exit()
    return


def get_default_nameserver():
    print('[*] getting default nameserver')
    lines = list(open('/etc/resolv.conf', 'r'))
    for line in lines:
        line = string.strip(line)
        if not line or line[0] == ';' or line[0] == '#':
            continue
        fields = string.split(line)
        if len(fields) < 2:
            continue
        if fields[0] == 'nameserver':
            defaults['nameserver'] = fields[1]
            return defaults


def get_default_source_ip():
    print('[*] getting default ip address')
    try:
        # get current used iface enstablishing temp socket
        ipsocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        ipsocket.connect(("gmail.com", 80))
        defaults['ipaddr'] = ipsocket.getsockname()[0]
        print('[*] found currently used interface ip ' + "'" +
                defaults['ipaddr'] + "'")
        ipsocket.close()
    except:
        print(''' [-] WARNING: can\'t get your ip-address, use "-i" option and
        define yourself''')
    return defaults


def parse_cmdline():
    p = OptionParser(usage=USAGE, version=VERSION)
    p.add_option('-t', dest='type',
            help='attack type (0 for dictionary 1 for bruteforce)')
    p.add_option('-a', dest='domain',
            help='subdomain to bruteforce')
    p.add_option('-l', dest='wordlist',
            help='wordlist, one hostname per line (default pprintefined in code)')
    p.add_option('-d', dest='dnshost',
            help='choose another nameserver (default your system\'s)')
    p.add_option('-i', dest='ipaddr',
            help='source ip address to use (default your systems\'s)')
    p.add_option('-p', dest='port', default=0,
            help='source port to use (default %default --> first free random'
                    'port) ' '\n\nnote: if fixed port, use max 1 thread!')
    p.add_option('-u', dest='protocol', default='udp',
            help='speak via udp or tcp (default %default)')
    p.add_option('-c', dest='charset', default=0,
            help='''choose charset 0 [a-z0-9], 1 [a-z] or 2 [0-9] (default '''
            '''%default)''')
    p.add_option('-m', dest='max', default=2,
            help='max chars to bruteforce (default %default)')
    p.add_option('-s', dest='prefix',
            help='prefix for bruteforce, e.g. "www" (default none)')
    p.add_option('-g', dest='postfix',
            help='postfix for bruteforce, e.g. "www" (default none)')
    p.add_option('-o', dest='timeout', default=3,
            help='timeout (default %defaults)')
    p.add_option('-v', action='store_true', dest='verbose',
            help='verbose mode - prints every attempt (default quiet)')
    p.add_option('-w', dest='wait', default=0,
            help='seconds to wait for next request (default %default)')
    p.add_option('-x', dest='threads', default=32,
            help='number of threads to use (default %default) - choose more :)')
    p.add_option('-r', dest='logfile', default='stdout',
            help='write found subdomains to file (default %default)')
    (opts, args) = p.parse_args()
    return opts


def check_cmdline(opts):
    if not opts.type or not opts.domain:
        print('[-] ERROR: mount /dev/brain')
        sys.exit()
    return


def set_opts(defaults, opts):
    if not opts.dnshost:
        opts.dnshost = defaults['nameserver']
    if not opts.ipaddr:
        opts.ipaddr = defaults['ipaddr']
    if int(opts.charset) == 0:
        opts.charset = chars + digits
    elif int(opts.charset) == 1:
        opts.charset = chars
    else:
        opts.charset = digits
    if not opts.prefix:
        opts.prefix = prefix
    if not opts.postfix:
        opts.postfix = postfix
    return opts


def read_hostnames(opts):
    print('[*] reading hostnames')
    hostnames = []
    if opts.wordlist:
        hostnames = list(open(opts.wordlist, 'r'))
        return hostnames
    else:
        return wordlist


def attack(opts, hostname, attack_pool):
    if opts.verbose:
        sys.stdout.write('  -> trying %s\n' % hostname)
        sys.stdout.flush()
    try:
        x = dns.message.make_query(hostname, 1)
        if opts.protocol == 'udp':
            a = dns.query.udp(x, opts.dnshost, float(opts.timeout), 53, None,
                    opts.ipaddr, int(opts.port), True, False)
        else:
            a = dns.query.tcp(x, opts.dnshost, float(opts.timeout), 53, None,
                    opts.ipaddr, int(opts.port), False)
        attack_pool.release()
    except dns.exception.Timeout:
        print('[-] ERROR: time out!')
        sys.exit()
    except socket.error:
        print('''[-] ERROR: no connection? ip|srcport incorrectly defined? you
        can run only one thread if fixed source port specified!''')
        sys.exit()
    if a.answer:
        answ = ''
        # iterate dns rrset answer (can be multiple sets) field to extract
        # detailed info (dns and ip)
        for i in a.answer:
            answ += str(i[0])
            answ += ' '
        answer = (hostname, answ)
        found.append(answer)
    else:
        pass
    return


def str_gen(opts, hostnames):
    print('[*] generating list of strings')
    tmp_hostnames = itertools.product(opts.charset, repeat=int(opts.max))
    hostnames = list(tmp_hostnames)
    hostnames = map(''.join, hostnames)
    return hostnames


def run_threads(opts, hostname, attack_pool, threads):
    t = threading.Thread(target=attack, args=(opts, hostname, attack_pool))
    attack_pool.acquire()
    t.start()
    threads.append(t)
    return threads


def prepare_attack(opts, hostnames):
    sys.stdout.write('[*] attacking \'%s\' via ' % opts.domain)
    threads = list()
    attack_pool = threading.BoundedSemaphore(value=int(opts.threads))
    if opts.type == '0':
        sys.stdout.write('dictionary\n')
        for hostname in hostnames:
            hostname = hostname.rstrip() + '.' + opts.domain
            time.sleep(float(opts.wait))
            threads = run_threads(opts, hostname, attack_pool, threads)
        for t in threads:
            t.join()
    elif opts.type == '1':
        sys.stdout.write('bruteforce\n')
        hostnames = str_gen(opts, hostnames)
        for hostname in hostnames:
            hostname = opts.prefix + hostname + opts.postfix + '.' + opts.domain
            time.sleep(float(opts.wait))
            threads = run_threads(opts, hostname, attack_pool, threads)
        for t in threads:
            t.join()
    else:
        print('[-] ERROR: unknown attack type')
        sys.exit()
    return


def ip_extractor(ip):
    #extract ip from string of rrset answer object
    try:
        extracted = re.findall(r'[0-9]+(?:\.[0-9]+){3}', ip)
        return extracted[0]
    except:
        print('[-] ERROR: can\'t extract ip addresses')
        sys.exit()


def analyze_results(opts, found):
    #get maindomain ip
    try:
        mainhostip = socket.gethostbyname(opts.domain)
        #append domain|ip to diffound if subdomain ip different than starting
        # domain ip
        ([diffound.append(domain + ' | ' + ip)
        for domain, ip in found if ip_extractor(ip) != mainhostip])
    except dns.exception.Timeout:
        sys.exit()
    except socket.error:
        print('[-] ERROR: wrong domain or no connection?')
        sys.exit()
    return


def log_results(opts, found, diffound):
    if opts.logfile == 'stdout':
        print('---')
        if not found:
            print('no hosts found :(')
        else:
            print('ANSWERED DNS REQUESTS')
            print('---')
            for f in found:
                print(f[0]+' | '+f[1])
        if not diffound:
            print('---')
            print('NO HOSTS WITH DIFFERENT IP FOUND :(')
        else:
            print('---')
            print('ANSWERED DNS REQUEST WITH DIFFERENT IP')
            print('---')
            for domain in diffound:
                print(domain)
    else:
        print('[+] \033[0;94mlogging results to %s\033[0;m' % opts.logfile)
        with open(opts.logfile, 'w') as f:
            if found:
                f.write('---\n')
                f.write('ANSWERED DNS REQUESTS\n')
                f.write('---\n')
                for x in found:
                    f.write('domain: '+x[0]+' | '+x[1]+ '\n')
            if not diffound:
                f.write('---\nNO HOSTS WITH DIFFERENT IP FOUND :(\n')
            else:
                f.write('---\nANSWERED DNS REQUEST WITH DIFFERENT IP\n---\n')
                for domain in diffound:
                    f.write(domain + '\n')
        f.close()
    print('[*] game over')
    return


def main():
    check_usage()
    opts = parse_cmdline()
    check_cmdline(opts)
    if not opts.dnshost:
        defaults = get_default_nameserver()
    if not opts.ipaddr:
        defaults = get_default_source_ip()
    if opts.protocol != 'udp' and opts.protocol != 'tcp':
        print('[-] ERROR: unknown protocol')
        sys.exit(1337)
    opts = set_opts(defaults, opts)
    hostnames = read_hostnames(opts)
    prepare_attack(opts, hostnames)
    analyze_results(opts, found)
    log_results(opts, found, diffound)
    return


if __name__ == '__main__':
    try:
        print(BANNER)
        main()
    except KeyboardInterrupt:
        print('\n[-] WARNING: aborted by user')
        raise SystemExit

# EOF
