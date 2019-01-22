import subprocess
from db.test import DatabaseTest
from db.ssh import SshTask

class Hostname(DatabaseTest):
    """Logs into the system and collects the hostname per what hostname -f spits out.
    """
    risk = DatabaseTest.INFO
    protocol = 'ssh'
    port = '40506'
    info = ''
    description_template = 'Test to see whether we can SSH to the host or not. [{}]'
    solution = 'n/a'

    def run(self, config):
        self.set_start_time()
        self.proc = SshTask(config, self.host, "hostname -f")
        self.proc.run()

    def poll(self):
        result = self.proc.poll()
        if result is not None:
            self.set_done_time()
        return result

    def finalize(self):
        (self.plugin_output, _) = self.proc.finalize()
        self.plugin_output = self.plugin_output.strip()
        if self.proc.task_state == SshTask.ERROR:
            self.status = DatabaseTest.FAILED
        else:
            self.status = DatabaseTest.PASSED

class MySQLDaemon(DatabaseTest):
    """Logs into the system and checks to make sure a MySQL daemon
    (mysqld) is actually running locally there.
    """
    risk = DatabaseTest.INFO
    protocol = 'ssh'
    port = '40506'
    info = ''
    description_template = 'Test to see if the MySQL Daemon is running on the host. [{}]'
    solution = 'n/a'

    def run(self, config):
        self.set_start_time()
        self.proc = SshTask(config, self.host, "ps -eo command | grep '^/.*mysqld'")
        self.proc.run()

    def poll(self):
        result = self.proc.poll()
        if result is not None:
            self.set_done_time()
        return result

    def finalize(self):
        (self.plugin_output, _) = self.proc.finalize()
        self.plugin_output = self.plugin_output.strip()
        if self.proc.task_state == SshTask.ERROR:
            self.status = DatabaseTest.FAILED
        else:
            self.status = DatabaseTest.PASSED
