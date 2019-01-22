import subprocess
from sys import argv


subprocess.call('sudo dpkg -l | grep openssh-server', shell=True)

proc = subprocess.Popen('sudo dpkg -l | grep openssh-server', shell=True, stdout=subprocess.PIPE)
output = proc.stdout.read()
print output
print "\n"

info = output.split()
print info[1]
print "package {} is installed at version {}" .format(info[1], info[2])