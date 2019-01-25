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
	print "\n \n The Affected hosts are as follows: \n \n "
	Hosts = []
	Index = 0
	for i in Host_list:
		print "{}) {}".format(Index, i)
		Hosts.append(i)
		Index = Index + 1
	return Host_list

#PARSE_HOSTS(Hosts)
print (PARSE_HOSTS(Hosts))