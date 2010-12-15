#!/bin/env python
#
# Copyright (c) 2009 Ma Can <ml.macana@gmail.com>
#                           <macan@ncic.ac.cn>
#
# Time-stamp: <2010-12-15 22:09:25 macan>
#
# Armed with EMACS.
#
# This file demoes a simple http access for Pomegranate REST API.
#

import httplib
import time

# Prepare a connection
conn = httplib.HTTPConnection("10.10.111.9:80")

# Build the header
headers = {
    "Host" : "hvfs://global",
    "Command" : "list",
    "Args" : "/",
    "Date" : time.ctime(),
    }

# Make a request and send it
conn.request("GET", "/hvfs", "", headers)

# Get the response
r1 = conn.getresponse()

# Read the response data and display them
data1 = r1.read()
print r1.status, r1.reason
print data1
