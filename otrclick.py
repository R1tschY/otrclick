#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Skript für das automatisierte Klicken von OTR-Bannern"""

__version__ = "0.4.3"

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

from optparse import OptionParser
from datetime import datetime

import time
import re
import urllib2

import random
import base64
import cookielib
import os
import urllib
import gzip
import StringIO
import socket
import xml.sax.saxutils as xmlutils

otrclick = None

RESULT_OK = 0
RESULT_IOERROR = 1
RESULT_NO_MORE_BANNER = 3
RESULT_SITE_CHANGED = 4
OTR = base64.b64decode("b25saW5ldHZyZWNvcmRlci5jb20=")
OTR_URL = base64.b64decode("aHR0cDovL3d3dy5vbmxpbmV0dnJlY29yZGVyLmNvbQ==")

def error(msg):
    if otrclick.options.verbose or (otrclick.xmlfile == None and not otrclick.options.quiet):
      print "!!!  Fehler:", msg

    if not otrclick.options.verbose and otrclick.xmlfile != None:
      otrclick.xmlfile.write_tag("error", msg)

def warning(msg):
    if otrclick.options.verbose or (otrclick.xmlfile == None and not otrclick.options.quiet):
      print "???  Warnung:", msg

    if not otrclick.options.verbose and otrclick.xmlfile != None:
      otrclick.xmlfile.write_tag("warning", msg)

def info(msg):
    if otrclick.options.verbose:
        print "--- ", msg

def escape_xml(data):
    return data.replace("&", "&amp;").replace(">", "&gt;").replace("<", "&lt;")\
      .replace("\"", "&quot;").replace("\'", "&#39;")

class SiteChangedError(Exception):
    def __init__(self, msg):
        self.msg = msg

    def __str__(self):
        return self.msg

    def __repr__(self):
        return self.__str__()

class RequestError(IOError):
    def __init__(self, url, msg):
        self.msg = msg
        self.url = url

    def __str__(self):
        return self.url + ": " + self.msg

    def __repr__(self):
        return self.__str__()

class HttpRequest:
    def getFirefoxVersion(self):
       version = round((datetime.now() - datetime(2013, 7, 17)).days / (6.*7.+2)) + 22
       return "Mozilla/5.0 (X11; Linux x86_64; rv:%.1f) Gecko/20100101 Firefox/%.1f" % (version, version)

    def __init__(self):
        self.spoofingheader = [("User-Agent", self.getFirefoxVersion()),
                               ("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"),
                               ("Accept-Language", "de-de,de;q=0.8,en-us;q=0.5,en;q=0.3"),
                               ("Accept-Encoding", "gzip,deflate"),
                               ("Accept-Charset", "ISO-8859-1,utf-8;q=0.7,*;q=0.7"),
                               ("Keep-Alive", "115")]
        self.userheaders = {}
        self.spoofing = False
        self.cookiefile = None
        self.hredirect = urllib2.HTTPRedirectHandler()
        self.hcookies = urllib2.HTTPCookieProcessor()
        self.opener = urllib2.build_opener(self.hredirect, self.hcookies)

    def close(self):
        if self.cookiefile != None:
            self.hcookies.cookiejar.save()

    def setUseragent(self, useragent):
        self.userheaders["User-Agent"] = useragent

    def setHeaderSpoofing(self, value=True):
        self.spoofing = value

    def loadRawPostRequest(self, url, data):
        if (self.spoofing):
            self.opener.addheaders = self.spoofingheader
        else:
            self.opener.addheaders = self.userheaders

        try:
            f = self.opener.open(url, data)
            if f.headers.get('Content-Encoding') == 'gzip':
                data = gzip.GzipFile(fileobj=StringIO.StringIO(f.read())).read()
                f.close()
                return data
            else:
                data = f.read()
                f.close()
                return data

        # für Python 2.4:
        except httplib.HTTPException, e:
            raise RequestError(url, "HTTP Fehler: " + str(e))

        # für Python 2.4:
        except urllib2.HTTPError, e:
            raise RequestError(url, "HTTP Fehlercode " + str(e.code))

        # für Python 2.4:
        except IOError, e:
            if isinstance(e.reason, socket.error):
                msg = e.reason[1]
            else:
                msg = str(e.reason)
            raise RequestError(url, msg)

        # für Python 2.4:
        except ValueError, e:
            raise RequestError(url, e.args[0].split(':')[0])

        # für Python 2.4:
        except Exception, e:
            raise RequestError(url, str(e))

    def loadPostRequest(self, url, data):
        return self.loadRawPostRequest(url, urllib.urlencode(data))

    def loadRequest(self, url):
        return self.loadRawPostRequest(url, None)

    def setCookiefile(self, filename):
        self.cookiefile = filename
        self.hcookies.cookiejar = cookielib.MozillaCookieJar(filename)
        if os.path.isfile(filename):
            self.hcookies.cookiejar.load()

    def setFullCookie(self, cookie):
        self.hcookies.cookiejar.set_cookie(cookie)

    def setCookie(self, name, value, domain, expires):
        self.setFullCookie(cookielib.Cookie(0, name, value,
                                        None, False,
                                        domain, True, True,
                                        "", False,
                                        False,
                                        expires,
                                        False, None, None, ""))

class Banner:
    def __init__(self):
        self.id = 0
        self.code = 0
        self.delay = 0
        self.rating = 0.0

    # Nur fürs Debugging
    def __str__(self):
        return "["+str(self.id)+"] -> "+self.target+" ^"+str(self.rating)+"^"

class BannerFinder:
    newct = 0.0
    bannerclicked = 0
    bannerclickedOld = -1
    banners = []
    possiblebanners = 0

    def __init__(self):
        self.adregex = re.compile(r"openBannerWindow\('([0-9]+)','([|0-9A-Z]+)'\)")
        self.clickedregex = re.compile(r"myclickinfo1'>([0-9]+)")

        self.visitedregex = re.compile(r"visited[0-9]+'>\s+(.+?)</span>")
        self.ctregex = re.compile(r"^([0-9\.]+)")

        self.process1regex = re.compile(r"\.location\.href='([^']+)'")
        self.process2regex = re.compile(r"process.php\?cs=[a-z0-9]+&bid=[0-9]+")
        self.clickregex = re.compile(r':"cs=([a-z0-9]+)&bid=([0-9]+)')

    def exist_banner_id(self, banner_id):
        for b in self.banners:
            if b.id == banner_id:
                return True
        return False

    def sort(self):
        sorted(self.banners, key=lambda banner: banner.rating, reverse=True)

    def click(self, banner):
        html = otrclick.request.loadRequest(OTR_URL + "/v2/partner/?bid="+str(banner.id)+"&code="+banner.code)
        r = self.process1regex.search(html)
        if r == None:
            raise SiteChangedError("Kann Bannerclickinformation nicht mehr holen (process1regex)")

        time.sleep(1)

        html = otrclick.request.loadRequest(OTR_URL + "/v2/partner/" + r.group(1))
        r = self.process2regex.search(html)
        if r == None:
            raise SiteChangedError("Kann Bannerclickinformation nicht mehr holen (process2regex)")

        html = otrclick.request.loadRequest(OTR_URL + "/v2/partner/" + r.group(0))
        r = self.clickregex.search(html)
        if r == None:
          raise SiteChangedError("Kann Bannerclickinformation nicht mehr holen (clickregex)")

        # eine Zeit warten
        time.sleep(random.randint(20, 35))

        # Klicken:
        result = otrclick.request.loadPostRequest(OTR_URL + "/v2/partner/credit.php",
            {"cs":r.group(1), "bid":r.group(2)})

        if result == "ERROR":
          warning(u"Bannerclick nicht erfolgreich: Banner schon geklicked?")
        elif result == "NOTALLOWED":
          warning(u"Bannerclick nicht erfolgreich: Sie haben über 60 Punkte und dürfen daher nur als Premium-User Banner klicken.")
        elif result == "INVALID":
          warning(u"Bannerclick nicht erfolgreich: Dieses Banner konnte im Moment nicht verarbeitet werden.")
        elif result == "TOOMUCH":
          warning(u"Bannerclick nicht erfolgreich: Sie haben heute schon die maximal erlaubte Anzahl an Bannern geklickt.")
        else:
          info('Bannerclick erfolgreich: #%d +%.2f' % (banner.id, banner.rating))
          self.newct += banner.rating
          self.bannerclicked += 1
          if self.bannerclickedOld == -1:
            self.bannerclickedOld = int(result) - 1

    def find(self, html):
        clicked = self.clickedregex.search(html)
        if clicked == None:
          warning("Kann Anzahl der Bannerclicks nicht finden")
        else:
          self.bannerclickedOld = int(clicked.group(1))

        visited = self.visitedregex.findall(html)
        banners = self.adregex.findall(html)
        for j in range(0, len(visited)):
            self.possiblebanners += 1

            ct = self.ctregex.search(visited[j])
            if ct != None: # Banner wurde noch nicht geklicked
              banner = Banner()
              banner.id = int(banners[j][0])
              banner.code = banners[j][1]
              banner.rating = float(ct.group(1))

              self.banners.append(banner)

        info("hab " + str(len(self.banners)) + " klickbare Banner / " + str(self.bannerclickedOld) + " wurde(n) schon geklicked")

class XmlLog:
    def __init__(self, filename):
        self.filename = filename
        self.newfile = False

    def open(self):
        try:
            f = open(self.filename, "r+")
        except (IOError):
            try:
                f = open(self.filename, "w")
            except (IOError):
                error(u"Kann Logfile nicht öffnen")
                return
            self.newfile = True;

        if (self.newfile):
            f.write(u"<log>\n")
        else:
            f.seek(-15, 2) #SEEK_END = 2
            endoffile = f.read(16)
            xmlend = endoffile.find("</log>")
            if (xmlend == -1):
                f.seek(0, 2) #SEEK_END = 2
            else:
                f.seek(-15 + xmlend, 2) #SEEK_END = 2

        self.f = f
        self.f.write(u"<session time=\"%s\">\n" % datetime.now().strftime("%d. %b %Y, %H:%M:%S"))

    def write_tag(self, tag, content):
        self.f.write(u"  <%s>%s</%s>\n" % (tag, xmlutils.escape(content), tag))

    def close(self):
        self.f.write(u"</session>\n</log>\n")
        self.f.close()


class OptParser:
    def __init__(self):
        self.parser = OptionParser(usage=u"Syntax: %prog [Optionen] --login=<email:password>", version="%prog "+__version__)

        self.parser.add_option("-l", "--login",
                               help=u"Logindaten setzen",
                               metavar="<email:password>")
        self.parser.add_option("-v", "--verbose",
                            action="store_true",
                            help=u"Informationen u:ber die durchgefu:hren Operationen ausgeben",
                            default=False)
        self.parser.add_option("-q", "--quiet",
                            action="store_true",
                            help=u"nichts ausgeben",
                            default=False)
        self.parser.add_option("-x", "--xmllog",
                            help=u"XML-Logfile fu:r Fehler und Statistik",
                            metavar="<file>")
        self.parser.add_option("-m", "--min",
                            help=u"nur Banner mit mehr Cents klicken",
                            type="float",
                            default=0.0,
                            metavar="<CENTS>")
        self.parser.add_option("-c", "--cookiefile",
                            help=u"Cookiefile fu:r Autologin",
                            metavar="<FILE>")
        self.parser.add_option("-n", "--number",
                            help=u"maximal so viele Banner klicken",
                            type="int",
                            default=10,
                            metavar="<NUMBER>")
        self.parser.add_option("-s", "--stat",
                            action="store_true",
                            default=False,
                            help=u"gibt Statistik zuru:ck")

    def parse(self, args = None):
        options = self.parser.parse_args(args=args)[0]

        if (options.login):
            if (options.login.find(":") != -1):
                (options.email, options.pwd) = options.login.split(":", 1)
            else:
                self.parser.error(u"falsches Argument für --login")

            if (len(options.email) == 0 or len(options.pwd) == 0):
                self.parser.error(u"falsches Argument für --login")
        else:
            self.parser.error(u"Argument --login muss gesetzt sein")

        if (options.number < 0 or options.number > 10):
            self.parser.error(u"falsches Argument für --number")

        if (options.min < 0.0 or options.min > 1.0):
            self.parser.error(u"falsches Argument für --min")

        if (options.quiet and options.verbose):
            self.parser.error(u"Optionen --quiet und --verbose schließen sich aus")

        if (options.quiet and options.stat):
            self.parser.error(u"Optionen --quiet und --stat schließen sich aus")

        options.autologin = options.cookiefile != None

        return options

class Otrclick:
    options = None
    xmlfile = None
    request = None
    bannerfinder = None

    def setOptions(self, options=None):
        if options == None:
            self.options = OptParser().parse()
        else:
            self.options = options

    def process(self):
        global otrclick

        if otrclick == None:
            otrclick = self

        info("Otrclick "+__version__)

        random.seed()

        self.request = HttpRequest()
        self.request.setHeaderSpoofing()

        if self.options.xmllog != None:
            self.xmlfile = XmlLog(self.options.xmllog)
            self.xmlfile.open()

        if self.options.cookiefile != None:
            self.request.setCookiefile(self.options.cookiefile)

        self.request.setCookie("clicked%s" % datetime.now().strftime("%Y%m%d"),
          "1", OTR, int(time.time()+ 2 *24*60*60*1000))

        try:
            # Startseite holen
            logined = False
            html = self.request.loadRequest(OTR_URL+'/v2/')

            if self.options.autologin:
              if html.find(r'<input type="password" name="password"') != -1:
                info("kein Autologin möglich")
              else:
                info("Autologin erfolgreich")
                logined = True

            # wenn Loginformular vorhanden ist, dann einloggen
            if not logined:
              info("Startseite erfolgreich geholt")
              if html.find(r'<input type="password" name="password"') != -1:
                  post = {"email": self.options.email, "password": self.options.pwd, "btn_login": " Anmelden "}
                  if self.options.autologin:
                      post.update({"rememberlogin": "on"})

                  html = self.request.loadPostRequest(OTR_URL+'/v2/?go=login', post)
                  if (html.find("Das Passwort ist nicht korrekt.") != -1):
                      error("Logindaten falsch!")
                      return
                  else:
                      info("Login erfolgreich")

                  if self.options.autologin:
                      # Autologin-Cookies suchen und setzen
                      i = re.search(r"'otr_password=([0-9a-f]*);", html)

                      if i != None:
                          t = int(time.time()) + 2508480000

                          self.request.setCookie("otr_email", self.options.email, OTR, t)
                          self.request.setCookie("otr_password", i.group(1), OTR, t)
                      else:
                          warning("Konnte Autologin-Javascript-Cookies nicht finden!")
              else:
                raise SiteChangedError("Login hat sich verändert")

            # Hole Banner
            info("Hole Banner")
            self.bannerfinder = BannerFinder()
            html = self.request.loadRequest(OTR_URL+'/v2/ajax/get_top_banner.php')
            self.bannerfinder.find(html)
            if self.bannerfinder.bannerclickedOld > 0:
                clickable = 10 - self.bannerfinder.bannerclickedOld
            else:
                clickable = 10

            if clickable < 1:
                warning("Heute schon alle Banner geklicked")
                return RESULT_NO_MORE_BANNER

            if self.bannerfinder.possiblebanners == 0:
                raise SiteChangedError("Kann Bannerlinks nicht mehr holen")

            if len(self.bannerfinder.banners) == 0:
                warning("Keine klickbaren Banner gefunden")
                return RESULT_OK

            self.bannerfinder.sort()

            toclick = min(self.options.number, clickable)

            # Banner klicken
            for banner in self.bannerfinder.banners:
                if self.bannerfinder.bannerclicked >= toclick or \
                   banner.rating < self.options.min:
                    break

                self.bannerfinder.click(banner)

                info(str(self.bannerfinder.bannerclicked)+" von "+str(toclick)+" Banner erfolgreich geklicked")

            if not self.options.stat:
                info("neue " + str(self.bannerfinder.newct) + " Cents")

            if otrclick.xmlfile != None:
                otrclick.xmlfile.f.write("  <click><id>0</id><gwp>%.2f</gwp><target>%d Banner geklicked</target></click>\n" % \
                                           (self.bannerfinder.newct, self.bannerfinder.bannerclicked))

        # für Python 2.4:
        except IOError, e:
            error(str(e))
            return RESULT_IOERROR
        # für Python 2.4:
        except SiteChangedError, e:
            if otrclick.xmlfile == None:
                error(u"Änderung der Seite: " + str(e))
            else:
                otrclick.xmlfile.write_tag("badstate", str(e))
            return RESULT_SITE_CHANGED

        return RESULT_OK

    def close(self):
        if self.request != None:
            self.request.close()

        if self.xmlfile != None:
            self.xmlfile.close()

        if self.options and self.options.stat:
            print "Neue Cents:",self.getNewCents()
            print "Geklickte Banner:",self.getClickedBanner()
            print "Noch klickbare Banner:",self.getStillClickableBanner()

    def getNewCents(self):
        if self.bannerfinder != None:
            return self.bannerfinder.newct
        else:
            return 0.0;

    def getClickedBanner(self):
        if self.bannerfinder != None:
            return self.bannerfinder.bannerclicked
        else:
            return 0;

    def getStillClickableBanner(self):
        if self.bannerfinder != None:
            return 10 - self.bannerfinder.bannerclickedOld - self.bannerfinder.bannerclicked
        else:
            return -1;

if __name__ == "__main__":
    otrclick = Otrclick()
    otrclick.setOptions()
    otrclick.process()
    otrclick.close()
