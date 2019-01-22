from sys import argv 
import subprocess


Script, HOSTS, PKG_FILE = argv
Txt = open(PKG_FILE, 'r')
#########################
''' Create a dictionary of service:package pairings that can be used to query 
on  aper host basis '''
Pkg_Dict = {}
#########################

def PARSE_HOSTS(Hosts):
	Txt = open(Hosts)
	Content = Txt.read() #call the read method of Txt and assign the result to Content
	Host_list = Content.split(',')
	return Host_list

def PRINT_LIST(L):
	print "\n \n These are the list elements: \n \n "
	Index = 0
	for i in L:
		print "{}) {}".format(Index, i)
		Index = Index + 1

def PROC_DPKG(Package):
	D_CMD = "sudo dpkg -l | grep {}".format(Package)
	subprocess.call(D_CMD, shell=True)


#proc = subprocess.Popen('sudo dpkg -l | grep openssh-server', shell=True, stdout=subprocess.PIPE)

for Line in Txt:
	Word = Line.split()
	#print word
	#print word[1] + " " + word[3]
	PName = Word[1]
	PVersion = []
	#PVersion = Word[3]
	Pkg_Dict[PName] = PVersion
''' This is where my SSH command will be plumbed in "PROC_DPKG() is an 
example just to generate local test data'''
	#PROC_DPKG(Word[1])

HOSTS = PARSE_HOSTS(argv[1])
PRINT_LIST(HOSTS)

import subprocess
from sys import argv


class Scrap:
	def parse(hosts):
		pass