from sys import argv 
import subprocess
import ssh_subprocess
import re
import mmap


Script, Hosts = argv


def PARSE_HOSTS(Hosts):
	Txt = open(Hosts)
	Content = Txt.read()
	Host_list = Content.split(',')
	Hosts = []
	Index = 0
	for vm_name in Host_list:
		vm_name = "{}.cgordon6.srvs.ahdev.co".format(vm_name)
		Hosts.append(vm_name)
		Index = Index + 1
	return Hosts

def Retrieve_Manifest(Host_name, cmd):
	config = "/home/cgordon/secure/ec2/hosting-dev/ssh/default"
	Task = ssh_subprocess.SshTask(config, Host_name, cmd)
	Task.run()
	Task.finalize(Host_name)

def package_builder(PKG_FILE):
	FH_packages = open(PKG_FILE, 'r')
	for Line in FH_packages:
		Words = Line.split()
		PName = Words[1]
		PVersion = Words[3]
		DICT_packages[PName] = PVersion
		package_names.append(PName)
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
	Retrieve_Manifest(Server, "sudo dpkg-query -W")

# Step 3) Parse the package list

PKG_FILE = "package-list"
DICT_packages = {}
package_names = []
package_builder(PKG_FILE)

	## Now we have a dictionary of name:value pairs for all the FIPS packages in 'DICT_packages'  ##

# Step 4) Cross reference the fips package with what's installed on the server

for Server in list_of_hosts:
	print "\n"
	print "########################################"
	print "###  {}".format(Server)
	print "########################################"
	print "\n"
	server_package_manifest = "{}-manifest.txt".format(Server)
	print "\nSearching for packages in {} \n".format(server_package_manifest)
	for fpkg_name in package_names:
		with open(server_package_manifest, 'r+') as fh:
			data = mmap.mmap(fh.fileno(), 0)
			result = re.search(r"({}.*)".format(fpkg_name), data)
			try:
				print "+++++\t{} was found at version \t{}".format(fpkg_name, result.groups())
			except AttributeError:
				pass
				print "{} NOT FOUND on {}".format(fpkg_name, Server)