import re

''' This is how I will parse the package manifest '''

fh = open('package.manifest')
for line in fh:
    # in python 2
    # print line
    # in python 3
    #print(line)
	pass
fh.close()

test_string = "ii  zsh-common                       5.1.1-1ubuntu2.3                                all          architecture independent files for Zsh"

match = re.match(r"ii\s+(\S+)\s+(\S+)", test_string)
print match
print match.groups()

'''first function loops over the lines and builds my dictionary
second function matches for each line given, extract the package name and version
'''