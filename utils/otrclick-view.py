#!/usr/bin/python
# -*- coding: utf-8 -*-

"""Skript für zur Ansicht von otrclick.py XML-Logfiles"""

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

# Konfiguration
path = "~/otrclick"
# Konfiguration Ende

import libxml2, sys, os
import time
import cgi
#import cgitb
#cgitb.enable()

def click_section (node, time):
	table = '<tr><td>Klick</td><td>'+ time +'</td>'
	child = node.children
	_gwpf = 0.0
	while child is not None:
		if child.type == "element":
			if child.name == 'gwp':
				_gwp = '<td>' + child.content + '</td>'
				_gwpf = float(child.content)
			elif child.name == 'target':
				_target = '<td>' + child.content + '</td>'
			elif child.name == 'id':
				_id = '<td>' + child.content + '</td>'
		child = child.next
	return table + _target + _id + _gwp + '</tr>', _gwpf
	
def format_size (size):
	if int(size) == 1:
		return str(size) + " Byte"
	elif size < 1024:
		return str(size) + " Bytes"
	elif size < 1024 ** 2:
		return "%.1f kB" % (size / 1024.0)
	elif size < 1024 ** 3:
		return "%.1f MB" % (size / 1024.0**2)
	else:
		return "%.1f GB" % (size / 1024.0**3)
    
def handleFatalError(msg):
	print "<h1 class=\"FatalError\">Fehler: " + msg + "</h1>"
	print "</body></html>"
	sys.exit()

# HTTP Header
print 'Content-Type: text/html'
print

print '''
<html>
<head>
	<meta http-equiv="content-type" content="text/html; charset=UTF-8">
	<script src="http://ajax.googleapis.com/ajax/libs/jquery/1.7.1/jquery.min.js" type="text/javascript"></script>
	<title>Otrclick Log</title>'''

print '''
<style type="text/css">
table {
	width: 100%;
  border-spacing: 0;
  margin-left: 5px;
}
table td{
	font-size: 11px;
}
body {
	color: #000;
	background-color: #FFF;
	font-family: Verdana, Sans, sans-serif;
  font-size: 11px;
  margin: 0 auto;
  width: 750px;
}
td:first-child {
  font-weight: bold;
  width: 75px;
}
td:nth-child(2) {
  width: 55px;
  text-align: center;
}
tr:nth-child(odd) {
  background: #DBDBDB
}
td:nth-child(4) {
  width: 75px;
  text-align: center;
}
td:nth-child(5) {
  width: 75px;
  text-align: center;
}
.itemheader {
	width: 100%;
	background-color: green;
	color: #fff;
  padding: 2px 5px;
  border-bottom: 1px solid gray;
  margin-bottom: 3px;
}
#errorinfo {
  display:none;
}
.item > table {
  display:none;
}
</style>
</head>
<body>
<script>
	$(document).ready(function(){
    $(".item").click(function () {
			$(this).find("table").toggle("slow");
		});
		
		$("#errormsg").click(function () { 
      $("#errorinfo").toggle("slow");
    });
	});
</script>


	<h1>Otrclick 0.4</h1>
	<h3>Otrclick-Utils 0.1.1</h3>
'''

# XML Auswertung
if path == "":
	path = os.path.join(os.path.expanduser("~"),".otrclick")

xmllogname = "log" + time.strftime("%m%Y") + ".xml"
if 'QUERY_STRING' in os.environ:
	query = cgi.parse_qs(os.environ['QUERY_STRING'])
	if 'file' in query:
		xmllogname = query['file'][0]

xmllog = os.path.join(path, xmllogname)

if not os.path.exists(path):
	handleFatalError("Verzeichniss nicht vorhanden!")

if not os.path.exists(xmllog):
	handleFatalError("Datei nicht vorhanden!")

doc = libxml2.parseFile(xmllog)
if doc.name != xmllog:
	handleFatalError("Konnte " + xmllog + " nicht laden")

root = doc.children
if root.name != "log":
	handleFatalError("Logdatei kaputt (Root != 'log')")
	
# error.log Auswertung
errorlogpath = os.path.join(path, "error.log")
if os.path.exists(errorlogpath):
	errorlog = open(errorlogpath)
	errorlogstr = errorlog.read()
	errorlog.close()
else:
	errorlogstr = None

# Verzeichniss Auswertung
filedates = []
for file in os.listdir(path):
  if file.startswith('log') and file.endswith('.xml') and len(file) is 13:
    filedates.append(time.strptime(file[3:9],"%m%Y"))

filedates.sort(reverse=True)
logfiletoolbar = ''
for filedate in filedates:
  displaydate = time.strftime("%B '%y", filedate)
  filenamedate = 'log'+time.strftime("%m%Y", filedate)+'.xml'
  logfiletoolbar += ' <a href="otrclick-view.py?file=' + filenamedate + '">'+ displaydate +'</a> '	

print logfiletoolbar
print '<div id="filesize">Logdateigröße: ', format_size(os.path.getsize(xmllog)), '</div>'	

if errorlogstr is not None:
	print '<b id="errormsg" style="color:red">Fehlerinformationen vorhanden</b>'
	print '<pre id="errorinfo">' + errorlogstr + '</pre>'

child = root.children
content = []
while child is not None:
	while child is not None and (child.type != "element" or child.name != 'session'):	
		child = child.next
	if child is None:
		break
	
	time_array = child.properties.children.content.split(',')
	date = lastdate = time_array[0]
	thistime = time_array[1]
	table = '<table>'
	badstate = []
	sessionsum = 0.0;
	errors = 0
	while date == lastdate:		
		schild = child.children
		while schild is not None:
			if schild.type == "element":
				if schild.name == 'click':
					cnt, newct = click_section(schild, thistime)
					sessionsum += newct
					table += cnt
				elif schild.name == 'download':
					table += '<tr><td>Verkehr</td><td>'+ thistime +'</td><td>' + schild.content + '</td><td></td><td></td></tr>'
				elif schild.name == 'warning':
					table += '<tr><td>Warnung</td><td>'+ thistime +'</td><td>' + schild.content + '</td><td></td><td></td></tr>'
				elif schild.name == 'error' or schild.name == 'badstate':
					table += '<tr><td>Fehler</td><td>'+ thistime +'</td><td>' + schild.content + '</td><td></td><td></td></tr>'
					errors += 1
			schild = schild.next
		
		child = child.next
		while child is not None and (child.type != "element" or child.name != 'session'):	
			child = child.next
		if child is None:
			break
		time_array = child.properties.children.content.split(',')
		date = time_array[0]
		thistime = time_array[1]
	item = '<div class="item"><div class="itemheader">'+lastdate+' <b>Cents: '+str(sessionsum)+'</b>'
	if errors > 0:
		item += ' :: <b> '+str(errors)+' Fehler</b>'
	item += '</div>'+table+"</table></div>"
	content.insert(0,item)
	if child is None:
		break

for item in content:
	print item

doc.freeDoc()

print '''
<br />
<br />
</body>
</html>
'''

