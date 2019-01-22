import re
import subprocess
import logging
from db.test import DatabaseTest
from db.ssh import SshTask

class MySQL56Identify(DatabaseTest):
    """Logs into the system and determines if MySQL 5.6 is running, and
    what version it is."""
    risk = DatabaseTest.INFO
    protocol = 'ssh'
    port = '40506'
    description_template = 'Test to see whether MySQL 5.6.x is available on the target host or not. [{}]'
    solution = 'n/a'

    def run(self, config):
        self.set_start_time()
        self.proc = SshTask(config, self.host, "mysql -s -e 'SELECT VERSION();'")
        logging.debug("MySQL56Identify command was '{}'".format(self.proc.ssh_cmd))
        self.proc.run()

    def poll(self):
        result = self.proc.poll()
        if result is not None:
            self.set_done_time()
        return result

    def finalize(self):
        (self.plugin_output, _) = self.proc.finalize()
        self.plugin_output = self.plugin_output.strip()
        if re.match(r'^5.6', self.plugin_output):
            self.status = DatabaseTest.PASSED
        else:
            self.status = DatabaseTest.NO_MATCH

