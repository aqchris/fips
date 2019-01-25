from sys import argv 
import subprocess


Script, PKG_FILE = argv


Txt = open(PKG_FILE, 'r')
Pkg_Pair = {}

for Line in Txt:
	Words = Line.split()
	PName = Words[1]
	PVersion = Words[3]
	Pkg_Pair[PName] = PVersion

Txt.close
print "\n#####################\n"
print Pkg_Pair["strongswan-tnc-pdp"]