import re
import mmap

''' This is how I will parse the package manifest 

fh = open('package.manifest')
   for pkg in  
    for line in fh:
        # in python 2
        # print line
        # in python 3
        #print(line)
        #pass
        pkg_match = re.match(r "", line)
fh.close()
'''
test_string = "ii  zsh-common                       5.1.1-1ubuntu2.3                                all          architecture independent files for Zsh"
test_var = "zsh-common"
fh = open('package-list')
#match = re.match(r"ii\s+(\S+)\s+(\S+)", test_string)
match = re.search(r"({})".format(test_var), test_string)
#print match
#print match.groups()
fh.close
'''first function loops over the lines and builds my dictionary
second function matches for each line given, extract the package name and version
'''
fh = open('package.manifest')
s = mmap.mmap(fh.fileno(), 0, access=mmap.ACCESS_READ)
if s.find(test_var) != -1:
    print('true')
print s.find(test_var)
fh.close

pkg = "openssh-server"
with open('package.manifest', 'r+') as fh:
  data = mmap.mmap(fh.fileno(), 0)
  mo = re.search(r"({})\s+(\S+)".format(pkg), data)
  if mo:
    print "found package", mo.group(1)
    print mo.groups()

