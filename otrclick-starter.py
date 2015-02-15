#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Skript für einfache Verwendung von otrclick.py"""

__version__ = "0.1.2"

__copyright__ = """
Copyright (c) 2010-2013 R1tschY.  All rights reserved.

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 3 of the License, or
(at your option) any later version.


This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
MA 02110-1301, USA.
"""

import os, sys
import time
import codecs

# Konfiguration
email = "mail@example.com"
pwd   = "password"
path  = ""
# Konfiguration Ende

# #### Einrichtung

if path == "":
    path = os.path.join(os.path.expanduser("~"),".otrclick")

if not os.path.exists(path):
    os.makedirs(path)

os.chdir(path)

args = sys.argv[1:]

# #### Debug

if "--help" in args:
    print "Benutzung: otrclick-starter.py [--debug] [otrclick.py options]"
    sys.exit()

debug_mode = "--debug" in args
if debug_mode:
    i = args.index("--debug")
    args = args[:i] + args[i+1:]
    verbose = "--verbose"
else:
    verbose = "--quiet"

# #### Blockfile
# Verhindert Aufrufe wenn schon alles geklicked wurde

day = time.strftime("%d%m%Y")
if os.path.exists("blockfile"):
    f = codecs.open("blockfile","r",encoding='utf-8')
    if day == f.read():
        f.close()
        if verbose == "--verbose":
          print "--- Schon alle Banner heute geclicked"
        sys.exit()
    f.close()

# #### Logfile

logfilename = "log" + time.strftime("%m%Y") + ".xml"

# #### Aufruf des Otrclick Scripts

import otrclick

session = otrclick.Otrclick()
try:
    session.setOptions(otrclick.OptParser()
                       .parse([verbose,
                               "--login", email + ":" + pwd,
                               "--xmllog", os.path.join(path, logfilename),
                               #"--cookiefile", os.path.join(path, "cookies.txt")
															 ]
                               + args))

    session.process()
    # TODO: prüfe rückgabewert
    if session.getStillClickableBanner() == 0:
        f = codecs.open("blockfile","w", encoding='utf-8')
        f.write(day)
        f.close()

    session.close()

# für Python 2.4
#  kein except exp as e
#  kein finally und except in gleichem try-Block
except Exception, e:
    import traceback
    
    if debug_mode:
    	print("!!! Exception:")
    	traceback.print_exc()    	

    f = codecs.open(os.path.join(path, "error.log"), "a", encoding='utf-8')
    f.write("!!! " + time.strftime("%H:%M %d.%m.%Y\n"))
    traceback.print_exc(file=f)
    f.close()

    session.close()




