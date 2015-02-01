#!/usr/bin/python

import httplib, string, sys
from modules import cmsvulns

bold = '\033[1m'
normal = '\033[0m'

## Dection function
def detect(target, dir, ssl):
    try:
        if ssl == True: ## Enables SSL
            conn = httplib.HTTPSConnection(target)
            conn.request("GET", dir)
            response = conn.getresponse()
            data = response.read()
            conn.close()

        else: ## Uses plain-text HTTP
            conn = httplib.HTTPConnection(target)
            conn.request("GET", dir)
            response = conn.getresponse()
            data = response.read()
            conn.close()

        for line in string.split(data, '\n'):
            if 'generator' in line:
                ver = line.split("\"")
                version = ver[3].split(" ")

		if version[0] == 'concrete5':
            		if len(version) == 3:
				print bold, "[+] Found", version[0], "at version", version[2], normal, "via generator tag"
                    		cmsvulns.vulncheck(version[2])
				break
			else:
				print bold, "[+] Found", version[0],  "installation", normal
		    		break
		else:
		    print bold, "[-] Not running concrete5!", normal
		    sys.exit(0)


	if not "/concrete/css/" in data:
		print bold, "[-] concrete5 installation not detected", normal
		sys.exit(0)

    except Exception, IndexError:
	pass

    except Exception, error:
	print error
	sys.exit(1)


def enumerate(target, dir, ssl):
	
	fullpath(target, dir, ssl)
	userenum(target, dir, ssl)

def fullpath(target, dir, ssl):
	try:

        	if ssl == True: ## Enables SSL
            		conn = httplib.HTTPSConnection(target)
            		conn.request("GET", dir + "concrete/blocks/content/editor_config.php")
            		response = conn.getresponse()
            		data = response.read()
            		conn.close()

        	else: ## Uses plain-text HTTP
            		conn = httplib.HTTPConnection(target)
            		conn.request("GET", dir + "concrete/blocks/content/editor_config.php")
            		response = conn.getresponse()
            		data = response.read()
            		conn.close()

		for line in string.split(data, '\n'):
			if 'Fatal error' in line:
				line = line.split(" ")
				line = line[8]
				length = len(line)
				length = length - 4
				fpd = line[3:length]

				print bold, "\n [+] Full Path Disclosure found!\r", normal
				print "", fpd, normal, "\r"
				
				if ssl == True:
					print " https://" + target + dir + "concrete/blocks/content/editor_config.php\n"
				else:
					print " http://" + target + dir + "concrete/blocks/content/editor_config.php\n"

	except Exception, error:
		print error


def userenum(target, dir, ssl):

        try:

       	        if ssl == True: ## Enables SSL
               	        conn = httplib.HTTPSConnection(target)
               	        conn.request("GET", dir + "index.php/members")
               	        response = conn.getresponse()
               	        data = response.read()
               	        conn.close()

               	else: ## Uses plain-text HTTP
                       	conn = httplib.HTTPConnection(target)
                       	conn.request("GET", dir + "index.php/members")
                       	response = conn.getresponse()
                       	data = response.read()
                       	conn.close()

               	for line in string.split(data, '\n'):
                       	if 'member-username' in line:
                       	        user = line.split(">")
                       	        user = user[2]
                               	user = user.split("<")
				user = user[0]
                               	print bold + "\r [+] Found username: " + normal + user
       	
	except Exception, error:
       	        print error
