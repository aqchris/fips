from sys import argv 
import subprocess


Script, Hosts = argv
'''Txt = open(Hosts)
Content = Txt.read()
'''

def PARSE_HOSTS(Hosts):
	Txt = open(Hosts)
	Content = Txt.read()
	Host_list = Content.split(',')
	print "\n \n The hosts in question are as follows: \n \n "
	Hosts = []
	Index = 0
	for i in Host_list:
		print "{}) {}".format(Index, i)
		Hosts.append(i)
		Index = Index + 1


def PROC_DPKG(Package):
	D_CMD = "sudo dpkg -l | grep {}".format(Package)
	subprocess.call(D_CMD, shell=True)
'''
Pkg = "openssh-server"
PROC_DPKG(Pkg)
'''

PARSE_HOSTS(Hosts)