import subprocess
import sys
import logging

'''
HOST="svn-2"
COMMAND="hostname"

#ssh = subprocess.Popen(["ssh", "%s" % HOST, COMMAND],
ssh = subprocess.Popen(["ssh ahlauncher@svn-2"],
                       shell=True,
                       stdout=subprocess.PIPE,
                       stderr=subprocess.PIPE)
result = ssh.stdout.readlines()
if result == []:
    error = ssh.stderr.readlines()
    print >>sys.stderr, "ERROR: %s" % error
else:
    print result
'''

BASTION_PORT='40506'
config = "ahlauncher"
hostname = "svn-2"
cmd = "hostname"

class SshTask:
    STARTED = 0
    ERROR = 1
    DONE = 2

    def __init__(self, hostname, cmd):
        self.task_state = SshTask.STARTED
        self.Host_name = hostname
        self.Command = cmd

    def start(self):
        """Starts the job, but waits until completion. Useful for debugging."""
        self.proc = subprocess.Popen("fssh {} {}".format(self.Host_name, self.Command),
                                     stdout=subprocess.PIPE,
                                     stderr=subprocess.PIPE,
                                     close_fds=True,
                                     shell=True)
        if self.proc.wait() == 0:
            a = self.proc.stdout.read()
            print a.__repr__()
        else:
            logging.error('Task failure for {}'.format(self.Command))

    def run(self):
        """Starts the job, but does not process."""
        self.proc = subprocess.Popen(self.Command,
                                     stdout=subprocess.PIPE,
                                     stderr=subprocess.PIPE,
                                     close_fds=True,
                                     shell=False)

    def poll(self):
        return self.proc.poll()

    def finalize(self):
        if self.proc.returncode == 0:
            self.task_state = SshTask.DONE
        else:
            self.task_state = SshTask.ERROR
        stdout = self.proc.stdout.read()
        stderr = self.proc.stderr.read()
        self.proc.stdout.close()
        self.proc.stderr.close()
        return (stdout, stderr)

