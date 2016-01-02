#     Otrclick

Otrclick ist ein Python Skript zur Automatisierung
von Bannerklicks auf OTR.

## VORRAUSETZUNGEN

python >= 2.4 (http://www.python.org/)

## INSTALLATION

Die Installation kann in ein beliebiges Verzeichnis erfolgen.

Bei der Benutzung von Otrclick-Utils muss darauf geachtet werden, das
`otrclick-starter.py` im gleichen Verzeichnis liegen muss wie `otrclick.py`.

## BENUTZUNG 

Syntax: `otrclick.py [Optionen] --login=<EMAIL-ADRESSE:PASSWORT>`

Damit Otrclick sich einloggen kann, benötigt es die E-Mail Adresse sowie
das	Passwort des OTR Accounts.

Weitere Optionen durch Aufruf von `./otrclick.py --help`.

Beispiel der Benutzung:
  
	./otrclick.py --login=maxmustermann@beispiel.de:password --number 3 --min 0.3

## WEITERVERBREITUNG

Otrclick steht unter GPL v3.
	
## UNTERSTÜTZUNG

Bei Fragen, Fehlern, Wünschen und Ähnlichen:

E-Mail: r1tschy@yahoo.de

Bugtracker: https://github.com/R1tschY/otrclick/issues

## TODO-LISTE

- bei `TOOMUCH` und `NOTALLOWED` abbrechen
- Vor erster Anfrage zufällige Zeit warten (über CLI-Option)
- wenn Seite nicht erreichbar nach bestimmter Zeit nochmal versuchen (3-mal)
	  
