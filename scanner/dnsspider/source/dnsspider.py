#!/usr/bin/env python2
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
# TODO:                                                                        #
# - attack while mutating -> don't generate whole list when using -t 1         #
#                                                                              #
# CHANGELOG:                                                                   #
# v0.6                                                                         #
# - upgraded default wordlist                                                  #
# - replaced optionparser with argparse                                        #
# - add version output option                                                  #
# - fixed typo                                                                 #
#                                                                              #
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
import argparse
try:
    import dns.message
    import dns.query
except ImportError:
    print("[-] ERROR: you need 'dnspython' package")
    sys.exit()


BANNER = '--==[ dnsspider by noptrix@nullsecurity.net ]==--'
USAGE = '\n\n' \
        '  dnsspider.py -t <arg> -a <arg> [options]'
VERSION = 'v0.6'

defaults = {}
hostnames = []
prefix = ''
postfix = ''
found = []
diffound = []
chars = string.ascii_lowercase
digits = string.digits

# default wordlist
wordlist = [
'0', '01', '02', '03', '1', '10', '11', '12', '13', '14', '15', '16', '17',
'18', '19', '2', '20', '3', '3com', '4', '5', '6', '7', '8', '9', 'ILMI', 'a',
'a.auth-ns', 'a01', 'a02', 'a1', 'a2', 'abc', 'about', 'ac', 'academico',
'acceso', 'access', 'accounting', 'accounts', 'acid', 'activestat', 'ad',
'adam', 'adkit', 'adm', 'admin', 'administracion', 'administrador',
'administrator', 'administrators', 'admins', 'ads', 'adserver', 'adsl', 'ae',
'af', 'affiliate', 'affiliates', 'afiliados', 'ag', 'agenda', 'agent', 'ai',
'aix', 'ajax', 'ak', 'akamai', 'al', 'alabama', 'alaska', 'albuquerque',
'alerts', 'alpha', 'alterwind', 'am', 'amarillo', 'americas', 'an', 'anaheim',
'analyzer', 'announce', 'announcements', 'antivirus', 'ao', 'ap', 'apache',
'apollo', 'app', 'app01', 'app1', 'apple', 'application', 'applications',
'apps', 'appserver', 'aq', 'ar', 'archie', 'arcsight', 'argentina', 'arizona',
'arkansas', 'arlington', 'as', 'as400', 'asia', 'asterix', 'at', 'athena',
'atlanta', 'atlas', 'att', 'au', 'auction', 'austin', 'auth', 'auto',
'autodiscover', 'autorun', 'av', 'aw', 'ayuda', 'az', 'b', 'b.auth-ns', 'b01',
'b02', 'b1', 'b2', 'b2b', 'b2c', 'ba', 'back', 'backend', 'backup', 'backups',
'baker', 'bakersfield', 'balance', 'balancer', 'baltimore', 'banking',
'bayarea', 'bb', 'bbdd', 'bbs', 'bd', 'bdc', 'be', 'bea', 'beta', 'bf', 'bg',
'bh', 'bi', 'bill', 'billing', 'biz', 'biztalk', 'bj', 'black', 'blackberry',
'blog', 'blogs', 'blue', 'bm', 'bn', 'bnc', 'bo', 'board', 'bob', 'bof',
'boise', 'bolsa', 'border', 'boston', 'boulder', 'boy', 'br', 'bravo', 'brazil',
'britian', 'broadcast', 'broker', 'bronze', 'brown', 'bs', 'bsd', 'bsd0',
'bsd01', 'bsd02', 'bsd1', 'bsd2', 'bt', 'bug', 'buggalo', 'bugs', 'bugzilla',
'build', 'bulletins', 'burn', 'burner', 'buscador', 'buy', 'bv', 'bw', 'by',
'bz', 'c', 'c.auth-ns', 'ca', 'cache', 'cafe', 'calendar', 'california', 'call',
'calvin', 'canada', 'canal', 'canon', 'careers', 'cart', 'catalog', 'cc', 'cd',
'cdburner', 'cdn', 'central', 'cert', 'certificates', 'certify', 'certserv',
'certsrv', 'cf', 'cg', 'cgi', 'ch', 'channel', 'channels', 'charlie',
'charlotte', 'chat', 'chats', 'chatserver', 'check', 'checkpoint', 'chi',
'chicago', 'ci', 'cims', 'cincinnati', 'cisco', 'citrix', 'ck', 'cl', 'class',
'classes', 'classifieds', 'classroom', 'cleveland', 'cli', 'clicktrack',
'client', 'clientes', 'clients', 'club', 'clubs', 'cluster', 'clusters', 'cm',
'cmail', 'cms', 'cn', 'co', 'cocoa', 'code', 'coldfusion', 'colombus',
'colorado', 'columbus', 'com', 'commerce', 'commerceserver', 'communigate',
'community', 'compaq', 'compras', 'con', 'concentrator', 'conf', 'conference',
'conferencing', 'confidential', 'connect', 'connecticut', 'consola', 'console',
'consult', 'consultant', 'consultants', 'consulting', 'consumer', 'contact',
'content', 'contracts', 'control', 'controller', 'core', 'core0', 'core01',
'corp', 'corpmail', 'corporate', 'correo', 'correoweb', 'cortafuegos',
'counterstrike', 'courses', 'cr', 'cricket', 'crm', 'crs', 'cs', 'cso', 'css',
'ct', 'cu', 'cust1', 'cust10', 'cust100', 'cust101', 'cust102', 'customer',
'customers', 'cv', 'cvs', 'cx', 'cy', 'cz', 'd', 'dallas', 'data', 'database',
'database01', 'database02', 'database1', 'database2', 'databases', 'datastore',
'datos', 'david', 'db', 'db0', 'db01', 'db02', 'db1', 'db2', 'dc', 'de',
'dealers', 'dec', 'def', 'default', 'defiant', 'delaware', 'dell', 'delta',
'delta1', 'demo', 'demonstration', 'demos', 'denver', 'depot', 'des',
'desarrollo', 'descargas', 'design', 'designer', 'desktop', 'detroit', 'dev',
'dev0', 'dev01', 'dev1', 'devel', 'develop', 'developer', 'developers',
'development', 'device', 'devserver', 'devsql', 'dhcp', 'dial', 'dialup',
'digital', 'dilbert', 'dir', 'direct', 'directory', 'disc', 'discovery',
'discuss', 'discussion', 'discussions', 'disk', 'disney', 'distributer',
'distributers', 'dj', 'dk', 'dm', 'dmail', 'dmz', 'dnews', 'dns', 'dns-2',
'dns0', 'dns1', 'dns2', 'dns3', 'do', 'doc', 'docs', 'document',
'documentacion', 'documentos', 'domain', 'domains', 'dominio', 'domino',
'dominoweb', 'doom', 'download', 'downloads', 'downtown', 'dragon', 'drupal',
'dsl', 'dyn', 'dynamic', 'dynip', 'dz', 'e', 'e-com', 'e-commerce', 'e0',
'eaccess', 'eagle', 'earth', 'east', 'ec', 'echo', 'ecom', 'ecommerce', 'edi',
'edu', 'education', 'edward', 'ee', 'eg', 'eh', 'ejemplo', 'elpaso', 'email',
'employees', 'empresa', 'empresas', 'en', 'enable', 'eng', 'eng01', 'eng1',
'engine', 'engineer', 'engineering', 'enterprise', 'epsilon', 'er', 'erp', 'es',
'esd', 'esm', 'espanol', 'estadisticas', 'esx', 'et', 'eta', 'europe', 'events',
'example', 'examples', 'exchange', 'exec', 'exit', 'ext', 'extern', 'external',
'extranet', 'f', 'f5', 'falcon', 'farm', 'faststats', 'fax', 'feedback',
'feeds', 'fi', 'field', 'file', 'files', 'fileserv', 'fileserver', 'filestore',
'filter', 'finance', 'find', 'finger', 'firewall', 'fix', 'fixes', 'fj', 'fk',
'fl', 'flash', 'florida', 'flow', 'fm', 'fo', 'foobar', 'formacion', 'foro',
'foros', 'fortworth', 'forum', 'forums', 'foto', 'fotos', 'foundry', 'fox',
'foxtrot', 'fr', 'france', 'frank', 'fred', 'freebsd', 'freebsd0', 'freebsd01',
'freebsd02', 'freebsd1', 'freebsd2', 'freeware', 'fresno', 'front', 'frontdesk',
'fs', 'fsp', 'ftp', 'ftp-', 'ftp0', 'ftp2', 'ftpserver', 'fw', 'fw-1', 'fw1',
'fwsm', 'fwsm0', 'fwsm01', 'fwsm1', 'g', 'ga', 'galeria', 'galerias',
'galleries', 'gallery', 'games', 'gamma', 'gandalf', 'gate', 'gatekeeper',
'gateway', 'gauss', 'gd', 'ge', 'gemini', 'general', 'george', 'georgia',
'germany', 'gf', 'gg', 'gh', 'gi', 'git', 'gl', 'glendale', 'gm', 'gmail', 'gn',
'go', 'gold', 'goldmine', 'golf', 'gopher', 'gp', 'gq', 'gr', 'green', 'group',
'groups', 'groupwise', 'gs', 'gsx', 'gt', 'gu', 'guest', 'gw', 'gw1', 'gy', 'h',
'hal', 'halflife', 'hawaii', 'hello', 'help', 'helpdesk', 'helponline', 'henry',
'hermes', 'hi', 'hidden', 'hk', 'hm', 'hn', 'hobbes', 'hollywood', 'home',
'homebase', 'homer', 'honeypot', 'honolulu', 'host', 'host1', 'host3', 'host4',
'host5', 'hotel', 'hotjobs', 'houstin', 'houston', 'howto', 'hp', 'hpc', 'hpov',
'hr', 'ht', 'http', 'https', 'hu', 'hub', 'humanresources', 'i', 'ia', 'ias',
'ibm', 'ibmdb', 'id', 'ida', 'idaho', 'ids', 'ie', 'iis', 'il', 'illinois',
'im', 'image', 'images', 'imail', 'imap', 'imap4', 'img', 'img0', 'img01',
'img02', 'imgs', 'in', 'inbound', 'inc', 'include', 'incoming', 'india',
'indiana', 'indianapolis', 'info', 'informix', 'inside', 'install', 'int',
'interface', 'intern', 'internal', 'international', 'internet', 'intl',
'intranet', 'invalid', 'investor', 'investors', 'io', 'iota', 'iowa', 'ip6',
'iplanet', 'ipmonitor', 'ipsec', 'ipsec-gw', 'ipv6', 'iq', 'ir', 'irc', 'ircd',
'ircserver', 'ireland', 'iris', 'irvine', 'irving', 'is', 'isa', 'isaserv',
'isaserver', 'ism', 'israel', 'isync', 'it', 'italy', 'ix', 'j', 'jabber',
'japan', 'java', 'jboss', 'je', 'jedi', 'jm', 'jo', 'jobs', 'john', 'jp',
'jrun', 'juegos', 'juliet', 'juliette', 'juniper', 'jupiter', 'k', 'kansas',
'kansascity', 'kappa', 'kb', 'ke', 'kentucky', 'kerberos', 'keynote', 'kg',
'kh', 'ki', 'kilo', 'king', 'km', 'kn', 'knowledgebase', 'knoxville', 'koe',
'korea', 'kp', 'kr', 'ks', 'kw', 'ky', 'kz', 'l', 'la', 'lab', 'laboratory',
'labs', 'lambda', 'lan', 'laptop', 'laserjet', 'lasvegas', 'launch', 'lb', 'lc',
'ldap', 'legal', 'leo', 'li', 'lib', 'library', 'lima', 'lincoln', 'link',
'linux', 'linux0', 'linux01', 'linux02', 'linux1', 'linux2', 'lista', 'lists',
'listserv', 'listserver', 'live', 'lk', 'load', 'loadbalancer', 'local',
'localhost', 'log', 'log0', 'log01', 'log02', 'log1', 'log2', 'logfile',
'logfiles', 'logger', 'logging', 'loghost', 'login', 'logs', 'london',
'longbeach', 'losangeles', 'lotus', 'louisiana', 'lr', 'ls', 'lt', 'lu', 'luke',
'lv', 'ly', 'lyris', 'm', 'ma', 'mac', 'mac1', 'mac10', 'mac11', 'mac2', 'mac3',
'mac4', 'mac5', 'mach', 'macintosh', 'madrid', 'mail', 'mail2', 'mailer',
'mailgate', 'mailhost', 'mailing', 'maillist', 'maillists', 'mailroom',
'mailserv', 'mailsite', 'mailsrv', 'main', 'maine', 'maint', 'mall', 'manage',
'management', 'manager', 'managers', 'manufacturing', 'map', 'mapas', 'maps',
'marketing', 'marketplace', 'mars', 'marvin', 'mary', 'maryland',
'massachusetts', 'master', 'max', 'mc', 'mci', 'md', 'mdaemon', 'me', 'media',
'member', 'members', 'memphis', 'mercury', 'merlin', 'messages', 'messenger',
'mg', 'mgmt', 'mh', 'mi', 'miami', 'michigan', 'mickey', 'midwest', 'mike',
'milwaukee', 'minneapolis', 'minnesota', 'mirror', 'mis', 'mississippi',
'missouri', 'mk', 'ml', 'mm', 'mn', 'mngt', 'mo', 'mobile', 'mom', 'monitor',
'monitoring', 'montana', 'moon', 'moscow', 'movies', 'mozart', 'mp', 'mp3',
'mpeg', 'mpg', 'mq', 'mr', 'mrtg', 'ms', 'ms-exchange', 'ms-sql', 'msexchange',
'mssql', 'mssql0', 'mssql01', 'mssql1', 'mt', 'mta', 'mtu', 'mu', 'multimedia',
'music', 'mv', 'mw', 'mx', 'mx01', 'my', 'mysql', 'mysql0', 'mysql01', 'mysql1',
'mz', 'n', 'na', 'name', 'names', 'nameserv', 'nameserver', 'nas', 'nashville',
'nat', 'nc', 'nd', 'nds', 'ne', 'nebraska', 'neptune', 'net', 'netapp',
'netdata', 'netgear', 'netmail', 'netmeeting', 'netscaler', 'netscreen',
'netstats', 'network', 'nevada', 'new', 'newhampshire', 'newjersey',
'newmexico', 'neworleans', 'news', 'newsfeed', 'newsfeeds', 'newsgroups',
'newton', 'newyork', 'newzealand', 'nf', 'ng', 'nh', 'ni', 'nigeria', 'nj',
'nl', 'nm', 'nms', 'nntp', 'no', 'noc', 'node', 'nokia', 'nombres', 'nora',
'north', 'northcarolina', 'northdakota', 'northeast', 'northwest', 'noticias',
'novell', 'november', 'np', 'nr', 'ns', 'ns-', 'ns0', 'ns01', 'ns02', 'ns1',
'ns2', 'ns3', 'ns4', 'ns5', 'nt', 'nt4', 'nt40', 'ntmail', 'ntp', 'ntserver',
'nu', 'null', 'nv', 'ny', 'nz', 'o', 'oakland', 'ocean', 'odin', 'office',
'offices', 'oh', 'ohio', 'ok', 'oklahoma', 'oklahomacity', 'old', 'om', 'omaha',
'omega', 'omicron', 'online', 'ontario', 'op', 'open', 'openbsd', 'openview',
'operations', 'ops', 'ops0', 'ops01', 'ops02', 'ops1', 'ops2', 'opsware', 'or',
'oracle', 'orange', 'order', 'orders', 'oregon', 'orion', 'orlando', 'oscar',
'out', 'outbound', 'outgoing', 'outlook', 'outside', 'ov', 'owa', 'owa01',
'owa02', 'owa1', 'owa2', 'ows', 'oxnard', 'p', 'pa', 'page', 'pager', 'pages',
'paginas', 'papa', 'paris', 'parners', 'partner', 'partners', 'patch',
'patches', 'paul', 'payroll', 'pbx', 'pc', 'pc01', 'pc1', 'pc10', 'pc101',
'pc11', 'pc12', 'pc13', 'pc14', 'pc15', 'pc16', 'pc17', 'pc18', 'pc19', 'pc2',
'pc20', 'pcmail', 'pda', 'pdc', 'pe', 'pegasus', 'pennsylvania', 'peoplesoft',
'personal', 'pf', 'pg', 'pgp', 'ph', 'phi', 'philadelphia', 'phoenix',
'phoeniz', 'phone', 'phones', 'photos', 'phpmyadmin', 'pi', 'pics', 'pictures',
'pink', 'pipex-gw', 'pittsburgh', 'pix', 'pk', 'pki', 'pl', 'plano', 'platinum',
'plesk', 'pluto', 'pm', 'pm1', 'pma', 'pn', 'po', 'policy', 'polls', 'pop',
'pop3', 'portal', 'portals', 'portfolio', 'portland', 'post', 'postales',
'postoffice', 'ppp1', 'ppp10', 'ppp11', 'ppp12', 'ppp13', 'ppp14', 'ppp15',
'ppp16', 'ppp17', 'ppp18', 'ppp19', 'ppp2', 'ppp20', 'ppp21', 'ppp3', 'ppp4',
'ppp5', 'ppp6', 'ppp7', 'ppp8', 'ppp9', 'pptp', 'pr', 'pre', 'prensa', 'press',
'printer', 'printserv', 'printserver', 'priv', 'privacy', 'private',
'problemtracker', 'products', 'profiles', 'project', 'projects', 'promo',
'proxy', 'prueba', 'pruebas', 'ps', 'psi', 'pss', 'pt', 'pub', 'public', 'pubs',
'purple', 'pw', 'py', 'q', 'qa', 'qmail', 'qotd', 'quake', 'quebec', 'queen',
'quotes', 'r', 'r01', 'r02', 'r1', 'r2', 'ra', 'rack', 'radio', 'radius',
'rapidsite', 'raptor', 'ras', 'rc', 'rcs', 'rd', 're', 'read', 'realserver',
'recruiting', 'red', 'redhat', 'ref', 'reference', 'reg', 'register',
'registro', 'registry', 'regs', 'relay', 'release', 'rem', 'remote', 'remstats',
'report', 'reports', 'research', 'reseller', 'reserved', 'resumenes', 'rho',
'rhodeisland', 'ri', 'ris', 'rmi', 'ro', 'robert', 'romeo', 'root', 'rose',
'route', 'router', 'router1', 'rs', 'rss', 'rtelnet', 'rtr', 'rtr01', 'rtr1',
'ru', 'rune', 'rw', 'rwhois', 's', 's1', 's2', 'sa', 'sac', 'sacramento',
'sadmin', 'safe', 'sales', 'saltlake', 'sam', 'san', 'sanantonio', 'sandiego',
'sanfrancisco', 'sanjose', 'saskatchewan', 'saturn', 'sb', 'sbs', 'sc',
'scanner', 'schedules', 'scotland', 'scotty', 'sd', 'se', 'search', 'seattle',
'sec', 'secret', 'secure', 'secured', 'securid', 'security', 'sendmail', 'seri',
'serv', 'serv2', 'server', 'server1', 'servers', 'service', 'services',
'servicio', 'servidor', 'setup', 'sg', 'sh', 'share', 'shared', 'sharepoint',
'shares', 'shareware', 'shipping', 'shop', 'shoppers', 'shopping', 'si',
'siebel', 'sierra', 'sigma', 'signin', 'signup', 'silver', 'sim', 'sirius',
'site', 'sj', 'sk', 'skywalker', 'sl', 'slackware', 'slmail', 'sm', 'smc',
'sms', 'smtp', 'smtphost', 'sn', 'sniffer', 'snmp', 'snmpd', 'snoopy', 'snort',
'so', 'socal', 'software', 'sol', 'solaris', 'solutions', 'soporte', 'source',
'sourcecode', 'sourcesafe', 'south', 'southcarolina', 'southdakota',
'southeast', 'southwest', 'spain', 'spam', 'spider', 'spiderman', 'splunk',
'spock', 'spokane', 'springfield', 'sprint', 'sqa', 'sql', 'sql0', 'sql01',
'sql1', 'sql7', 'sqlserver', 'squid', 'squirrel', 'squirrelmail', 'sr', 'srv',
'ss', 'ssh', 'ssl', 'ssl0', 'ssl01', 'ssl1', 'st', 'staff', 'stage', 'stage1',
'staging', 'start', 'stat', 'static', 'statistics', 'stats', 'stlouis', 'stock',
'storage', 'store', 'storefront', 'streaming', 'stronghold', 'strongmail',
'studio', 'submit', 'subversion', 'sun', 'sun0', 'sun01', 'sun02', 'sun1',
'sun2', 'superman', 'supplier', 'suppliers', 'support', 'sv', 'svn', 'sw',
'sw0', 'sw01', 'sw1', 'sweden', 'switch', 'switzerland', 'sy', 'sybase',
'sydney', 'sysadmin', 'sysback', 'syslog', 'syslogs', 'system', 'sz', 't',
'tacoma', 'taiwan', 'talk', 'tampa', 'tango', 'tau', 'tc', 'tcl', 'td', 'team',
'tech', 'technology', 'techsupport', 'telephone', 'telephony', 'telnet', 'temp',
'tennessee', 'terminal', 'terminalserver', 'termserv', 'test', 'test2k',
'testbed', 'testing', 'testlab', 'testlinux', 'tests', 'testserver', 'testsite',
'testsql', 'testxp', 'texas', 'tf', 'tftp', 'tg', 'th', 'thailand', 'theta',
'thor', 'tienda', 'tiger', 'time', 'titan', 'tivoli', 'tj', 'tk', 'tm', 'tn',
'to', 'tokyo', 'toledo', 'tom', 'tool', 'tools', 'toplayer', 'toronto', 'tour',
'tp', 'tr', 'tracker', 'train', 'training', 'transfers', 'trinidad', 'trinity',
'ts', 'ts1', 'tt', 'tucson', 'tulsa', 'tunnel', 'tv', 'tw', 'tx', 'tz', 'u',
'ua', 'uddi', 'ug', 'uk', 'um', 'uniform', 'union', 'unitedkingdom',
'unitedstates', 'unix', 'unixware', 'update', 'updates', 'upload', 'uploads',
'ups', 'upsilon', 'uranus', 'urchin', 'us', 'usa', 'usenet', 'user', 'users',
'ut', 'utah', 'utilities', 'uy', 'uz', 'v', 'va', 'vader', 'vantive', 'vault',
'vc', 've', 'vega', 'vegas', 'vend', 'vendors', 'venus', 'vermont', 'vg', 'vi',
'victor', 'video', 'videos', 'viking', 'violet', 'vip', 'virginia', 'virtual',
'vista', 'vm', 'vmserver', 'vmware', 'vn', 'vnc', 'voice', 'voicemail', 'voip',
'voyager', 'vpn', 'vpn0', 'vpn01', 'vpn02', 'vpn1', 'vpn2', 'vt', 'vu', 'vz',
'w', 'w1', 'w2', 'w3', 'wa', 'wais', 'wallet', 'wam', 'wan', 'wap', 'warehouse',
'washington', 'wc3', 'web', 'webaccess', 'webadmin', 'webalizer', 'webboard',
'webcache', 'webcam', 'webcast', 'webdev', 'webdocs', 'webfarm', 'webhelp',
'weblib', 'weblogic', 'webmail', 'webmaster', 'webmin', 'webproxy', 'webring',
'webs', 'webserv', 'webserver', 'webservices', 'webshop', 'website', 'websites',
'websphere', 'websrv', 'websrvr', 'webstats', 'webstore', 'websvr', 'webtrends',
'welcome', 'west', 'westvirginia', 'wf', 'whiskey', 'white', 'whois', 'wi',
'wichita', 'wiki', 'wililiam', 'win', 'win01', 'win02', 'win1', 'win2',
'win2000', 'win2003', 'win2k', 'win2k3', 'windows', 'windows01', 'windows02',
'windows1', 'windows2', 'windows2000', 'windows2003', 'windowsxp', 'wingate',
'winnt', 'winproxy', 'wins', 'winserve', 'winxp', 'wire', 'wireless',
'wisconsin', 'wlan', 'wordpress', 'work', 'workstation', 'world', 'wpad',
'write', 'ws', 'ws1', 'ws10', 'ws11', 'ws12', 'ws13', 'ws2', 'ws3', 'ws4',
'ws5', 'ws6', 'ws7', 'ws8', 'ws9', 'wusage', 'wv', 'ww', 'www', 'www-',
'www-01', 'www-02', 'www-1', 'www-2', 'www-int', 'www0', 'www01', 'www02',
'www1', 'www2', 'www3', 'wwwchat', 'wwwdev', 'wwwmail', 'wy', 'wyoming', 'x',
'x-ray', 'xi', 'xlogan', 'xmail', 'xml', 'xp', 'y', 'yankee', 'ye', 'yellow',
'young', 'yt', 'yu', 'z', 'z-log', 'za', 'zebra', 'zera', 'zeus', 'zlog', 'zm',
'zulu', 'zw' ]


def usage():
    print('\n' + USAGE)
    sys.exit()
    return


def check_usage():
    if len(sys.argv) == 1:
        print('[!] WARNING: use -H for help and usage')
        sys.exit()
    return


def get_default_nameserver():
    print('[+] getting default nameserver')
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
    print('[+] getting default ip address')
    try:
        # get current used iface enstablishing temp socket
        ipsocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        ipsocket.connect(("gmail.com", 80))
        defaults['ipaddr'] = ipsocket.getsockname()[0]
        print('[+] found currently used interface ip ' + "'" +
                defaults['ipaddr'] + "'")
        ipsocket.close()
    except:
        print(''' [!] WARNING: can\'t get your ip-address, use "-i" option and
        define yourself''')
    return defaults


def parse_cmdline():
    p = argparse.ArgumentParser(usage=USAGE, add_help=False)
    p.add_argument(
            '-t',
            metavar='<type>',
            dest='type',
            help='attack type (0 for dictionary 1 for bruteforce)'
            )
    p.add_argument(
            '-a',
            metavar='<domain>',
            dest='domain',
            help='subdomain to bruteforce'
            )
    p.add_argument(
            '-l',
            metavar='<wordlist>',
            dest='wordlist',
            help='wordlist, one hostname per line (default: predefined in code)'
            )
    p.add_argument(
            '-d',
            metavar='<nameserver>',
            dest='dnshost',
            help="choose another nameserver (default: your system's)"
            )
    p.add_argument(
            '-i',
            metavar='<ipaddr>',
            dest='ipaddr',
            help="source ip address to use (default: your system's)"
            )
    p.add_argument(
            '-p',
            metavar='<port>',
            dest='port',
            default=0,
            help='source port to use (default: 0 --> first free random port)'
            )
    p.add_argument(
            '-u',
            metavar='<protocol>',
            dest='protocol',
            default='udp',
            help='speak via udp or tcp (default: udp)'
            )
    p.add_argument(
            '-c',
            metavar='<charset>',
            dest='charset',
            default=0,
            help='choose charset 0 [a-z0-9], 1 [a-z] or 2 [0-9] (default: 0)'
            )
    p.add_argument(
            '-m',
            metavar='<maxchar>',
            dest='max',
            default=2,
            help='max chars to bruteforce (default: 2)'
            )
    p.add_argument(
            '-s',
            metavar='<prefix>',
            dest='prefix',
            help="prefix for bruteforce, e.g. 'www'"
            )
    p.add_argument(
            '-g',
            metavar='<postfix>',
            dest='postfix',
            help="postfix for bruteforce, e.g. 'www'"
            )
    p.add_argument(
            '-o',
            metavar='<sec>',
            dest='timeout',
            default=3,
            help='timeout (default: 3)'
            )
    p.add_argument(
            '-v',
            action='store_true',
            dest='verbose',
            help='verbose mode - prints every attempt (default: quiet)'
            )
    p.add_argument(
            '-w',
            metavar='<sec>',
            dest='wait',
            default=0,
            help='seconds to wait for next request (default: 0)'
            )
    p.add_argument(
            '-x',
            metavar='<num>',
            dest='threads',
            default=32,
            help='number of threads to use (default: 32) - choose more :)'
            )
    p.add_argument(
            '-r',
            metavar='<logfile>',
            dest='logfile',
            default='stdout',
            help='write found subdomains to file (default: stdout)'
            )
    p.add_argument(
            '-V',
            action='version',
            version='%(prog)s ' + VERSION,
            help='print version information'
            )
    p.add_argument(
            '-H',
            action='help',
            help='print this help'
            )
    return(p.parse_args())


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
    print('[+] reading hostnames')
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
    print('[+] generating list of strings')
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
    sys.stdout.write('[+] attacking \'%s\' via ' % opts.domain)
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
    print('[+] game over')
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
        print(BANNER + '\n')
        main()
    except KeyboardInterrupt:
        print('\n[!] WARNING: aborted by user')
        raise SystemExit

# EOF
