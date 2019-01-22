from sys import argv 
import subprocess


Script, PKG_FILE = argv


Txt = open(PKG_FILE, 'r')
Pkg_Pair = {}

for Line in Txt:
	Word = Line.split()
	#print word
	#print word[1] + " " + word[3]
	PName = Word[1]
	PVersion = Word[3]
	Pkg_Pair[PName] = PVersion
	print Pkg_Pair