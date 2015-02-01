#!/usr/bin/python

## client.py
## This file handle all http(s) network connectivity

import httplib, sys, urllib


## Module for all get requests over https
def https_get(target, dir):

    try:
        conn = httplib.HTTPSConnection(target)
        conn.request("GET", dir)
        response = conn.getresponse()
        data = response.read()
        conn.close()

	return data

    except Exception, error:
	print error


## Module for all get requests over http
def http_get(target, dir):

    try:
        conn = httplib.HTTPConnection(target)
        conn.request("GET", dir)
        response = conn.getresponse()
        data = response.read()
        conn.close()

        return data

    except Exception, error:
        print error


## Module for all post requests over https
def https_post(target, dir, params):

    headers = {"Content-type": "application/x-www-form-urlencoded", "Accept": "text/plain", "Cookie":"CONCRETE5=1234"}

    try:
        conn = httplib.HTTPSConnection(target)
        conn.request("POST", dir, params, headers)
        response = conn.getresponse()
        data = response.read()
        status = response.status
        conn.close()

        return data, status

    except Exception, error:
        print error


## Module for all post requests over http
def http_post(target, dir, params):

    headers = {"Content-type": "application/x-www-form-urlencoded", "Accept": "text/plain", "Cookie":"CONCRETE5=1234"}

    try:
        conn = httplib.HTTPConnection(target)
        conn.request("POST", dir, params, headers)
        response = conn.getresponse()
        data = response.read()
	status = response.status
        conn.close()
	return data, status

    except Exception, error:
        print error

