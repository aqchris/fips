from sys import argv 
import subprocess
import ssh_subprocess


Script, Hosts = argv


def PARSE_HOSTS(Hosts):
	Txt = open(Hosts)
	Content = Txt.read()
	Host_list = Content.split(',')
	#print "\n \n The hosts in question are as follows: \n \n "
	Hosts = []
	Index = 0
	for vm_name in Host_list:
	#	print "{}) {}".format(Index, i)
		vm_name = "{}.cgordon6.srvs.ahdev.co".format(vm_name)
		Hosts.append(vm_name)
		Index = Index + 1
	return Hosts

def Retrieve_Manifest(Host_name, cmd):
	config = "/home/cgordon/secure/ec2/hosting-dev/ssh/default"
	Task = ssh_subprocess.SshTask(config, Host_name, cmd)
#	Task.start()
	Task.run()
	Task.finalize(Host_name)
	#Retrieve_Manifest("svn-2.cgordon6.srvs.ahdev.co", "sudo dpkg -l")

def package_builder(PKG_FILE):
	FH_packages = open(PKG_FILE, 'r')
	for Line in FH_packages:
		Words = Line.split()
		PName = Words[1]
		PVersion = Words[3]
		DICT_packages[PName] = PVersion
	FH_packages.close
	'''print "\n#####################\n"
	print DICT_packages["strongswan-tnc-pdp"] '''

### The main function begins here ###

# Step 1) Parse the initial string of hostnames and then selet a host to work with

list_of_hosts = PARSE_HOSTS(Hosts)

# Step 2) Take the host list and go grab the packages that belong to that server

for Server in list_of_hosts:
	print "< < Generating package manifest for {}".format(Server)
	print "\n"
	Retrieve_Manifest(Server, "sudo dpkg -l")

# Step 3) Parse the package list

PKG_FILE = "package-list"
DICT_packages = {}
package_builder(PKG_FILE)

	## Now we have a dictionary of name:value pairs for all the FIPS packages in 'DICT_packages'  ##

# Step 4) Cross reference the fips package with what's installed on the server

for Server in list_of_hosts:
	print "\t###\t{}\t###".format(Server)
	server_package_manifest = "{}-manifest.txt".format(Server)
	for fips_pkg_name in 
