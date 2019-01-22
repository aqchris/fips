from sys import argv 
import subprocess
import ssh_sub_process


#cript, HOSTS, PKG_FILE = argv
#Txt = open(PKG_FILE, 'r')
#########################
''' Create a dictionary of service:package pairings that can be used to query 
on  aper host basis '''
#Pkg_Dict = {}
#########################

def PARSE_HOSTS(Hosts):
	Txt = open(Hosts)
	Content = Txt.read() #call the read method of Txt and assign the result to Content
	Host_list = Content.split(',')
	Txt.close()
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



##########################################33

def retrieve_package_manifest(Host_name):
	Task = ssh_sub_process.SshTask(Host_name, "hostname")
	Task.start()
	output,errors = Task.finalize()
	print errors
	print output

retrieve_package_manifest("svn-2")

