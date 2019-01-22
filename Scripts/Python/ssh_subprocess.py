import subprocess
import sys


BASTION_PORT='40506'
user = "ahlauncher"


class SshTask:
    STARTED = 0
    ERROR = 1
    DONE = 2

    def __init__(self, config, hostname, cmd):
        self.task_state = SshTask.STARTED
        self.ssh_cmd = ['/usr/bin/ssh',
                        '-A', # agent forwarding, set by fssh so we copy here
                        '-p', BASTION_PORT, # fssh default is 40506
                        '-i', config,
                        '-o', 'StrictHostKeyChecking=no',
                        '-o', 'CheckHostIP=no', # on by default
                        '-o', 'GlobalKnownHostsFile=/dev/null',
                        '-o', 'UserKnownHostsFile=/dev/null',
                        '-o', 'ControlMaster=auto',
                        '-o', 'ControlPath=/tmp/ssh_mux_%%h_%%p_%%r',
                        "{}@{}".format(user, hostname),
                        cmd]
    def start(self):
        """Starts the job, but waits until completion. Useful for debugging."""
        self.proc = subprocess.Popen(self.ssh_cmd,
                                     stdout=subprocess.PIPE,
                                     stderr=subprocess.PIPE,
                                     close_fds=True,
                                     shell=False)
        if self.proc.wait() == 0:
            a = self.proc.stdout.read()
            print a.__repr__()
        else:
            print "Error"
            #logging.error('Task failure for {}'.format(self.ssh_cmd))

    def run(self):
        """Starts the job, but does not process."""
        self.proc = subprocess.Popen(self.ssh_cmd,
                                     stdout=subprocess.PIPE,
                                     stderr=subprocess.PIPE,
                                     close_fds=True,
                                     shell=False)

    def poll(self):
        return self.proc.poll()

    def finalize(self, Host_name):
        if self.proc.returncode == 0:
            self.task_state = SshTask.DONE
        else:
            self.task_state = SshTask.ERROR
        stdout = self.proc.stdout.read()
        stderr = self.proc.stderr.read()
        '''Added the next four lines to spit the output to a file for local processing'''
        Host_name = Host_name
        manifest = open("{}-manifest.txt".format(Host_name), 'w')
        manifest.write(stdout)
        manifest.close()
        self.proc.stdout.close()
        self.proc.stderr.close()
        return (stdout, stderr)


