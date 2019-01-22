import re
import logging
from db.test import DatabaseTest
from db.ssh import SshTask

# TODO: Automate this by checking
# https://repo.percona.com/apt/dists/xenial/main/binary-amd64/ for the
# percona MySQL's
MYSQL_LATEST_VERSION = r"^5.6.39-83.1"

# This file loosely follows the Nessus format, and we add a new local
# parameter called 'benchmark' which is a way to find particular
# tests.


class DatabasePartition(DatabaseTest):
    """Tests and ensures the database is not on the 'system'
    partition. The 'system' partition means the root OS partition. In
    the legacy MySQL fsdb implementation this data is mounted on
    /vol/ebs1. All this test does is make sure it's not root.
    """
    benchmark = '1.1'
    risk = DatabaseTest.HIGH
    protocol = 'ssh+mysql'
    port = '40506'
    description_template = '1.1 Place Databases on Non-System Partitions [{}]'
    info = """It is generally accepted that host operating systems should include different filesystem partitions for different purposes. One set of filesystems are typically called 'system partitions', and are generally reserved for host system/application operation. The other set of filesystems are typically called 'non-system partitions', and such locations are generally reserved for storing data.

This test was modified by Acquia."""
    solution = """Perform the following steps to remediate this setting:
   1. Choose a non-system partition new location for the MySQL data
   2. Stop mysqld using a command like: service mysql stop
   3. Copy the data using a command like: cp -rp <datadir Value> <new location>
   4. Set the datadir location to the new location in the MySQL configuration file
   5. Start mysqld using a command like: service mysql start

   NOTE: On some Linux distributions you may need to additionally modify apparmor settings. For example, on a Ubuntu 14.04.1 system edit the file /etc/apparmor.d/usr.sbin.mysqld so that the datadir access is appropriate. The original might look like this:
   # Allow data dir access
   /var/lib/mysql/ r,
   /var/lib/mysql/** rwk,

   Alter those two paths to be the new location you chose above. For example, if that new location were /media/mysql, then the /etc/apparmor.d/usr.sbin.mysqld file should include something like this:
   # Allow data dir access
   /media/mysql/ r,
   /media/mysql/** rwk,"""
    reference = '800-53|SC-5,CSF|PR.DS-4,ITSG-33|SC-5,LEVEL|1S'
    see_also = 'https://benchmarks.cisecurity.org/tools2/mysql/CIS_Oracle_MySQL_Community_Server_5.6_Benchmark_v1.1.0.pdf'

    def run(self, config):
        self.set_start_time()
        self.proc = SshTask(config, self.host, "df --output=target $(mysql -sN -e \"show variables like 'datadir'\"|awk '{print $2}')")
        logging.debug("MySQL 5.6 DatabasePartition command was '{}'".format(self.proc.ssh_cmd))
        self.proc.run()

    def poll(self):
        result = self.proc.poll()
        if result is not None:
            self.set_done_time()
        return result

    def finalize(self):
        (self.plugin_output, _) = self.proc.finalize()
        self.plugin_output = self.plugin_output.strip()
        for i in self.plugin_output.splitlines():
            if re.match(r'^/$', i):
                self.status = DatabaseTest.FAILED
        self.status = DatabaseTest.PASSED


class DedicatedMySQLAccount(DatabaseTest):
    benchmark = '1.2'
    risk = DatabaseTest.HIGH
    protocol = 'ssh+mysql'
    port = '40506'
    description_template = '1.2 Use Dedicated Least Privileged Account for MySQL Daemon/Service [{}]'
    info = """It is generally accepted that host operating systems should include different filesystem partitions for different purposes. One set of filesystems are typically called 'system partitions', and are generally reserved for host system/application operation. The other set of filesystems are typically called 'non-system partitions', and such locations are generally reserved for storing data.
"""
    solution = """
Create a user which is only used for running MySQL and directly related processes. This
user must not have administrative rights to the system.
"""
    reference = '800-53|SC-5,CSF|PR.DS-4,ITSG-33|SC-5,LEVEL|1S'
    see_also = 'https://benchmarks.cisecurity.org/tools2/mysql/CIS_Oracle_MySQL_Community_Server_5.6_Benchmark_v1.1.0.pdf'

    def run(self, config):
        self.set_start_time()
        self.proc = SshTask(config, self.host, "ps -eo user,command | grep ^mysql")
        logging.debug("MySQL 5.6 DedicatedMySQLAccount command was '{}'".format(self.proc.ssh_cmd))
        self.proc.run()

    def poll(self):
        result = self.proc.poll()
        if result is not None:
            self.set_done_time()
        return result

    def finalize(self):
        (self.plugin_output, _) = self.proc.finalize()
        self.plugin_output = self.plugin_output.strip()
        for i in self.plugin_output.splitlines():
            if re.match(r'^mysql.*/usr/sbin/mysqld.*--user=mysql', i):
                self.status = DatabaseTest.PASSED
                return
        self.status = DatabaseTest.FAILED


class DisableMySQLHistory(DatabaseTest):
    benchmark = '1.3'
    risk = DatabaseTest.HIGH
    protocol = 'ssh+mysql'
    port = '40506'
    description_template = '1.3 Disable MySQL Command History [{}]'
    info = """On Linux/UNIX, the MySQL client logs statements executed interactively to a history
file. By default, this file is named .mysql_history in the user's home directory. Most
interactive commands run in the MySQL client application are saved to a history file. The
MySQL command history should be disabled.
"""
    solution = """
Perform the following steps to remediate this setting:
1. Remove .mysql_history if it exists.
2. Use either of the techniques below to prevent it from being created again:
1. Set the MYSQL_HISTFILE environment variable to /dev/null. This
will need to be placed in the shell's startup script.
2. Create $HOME/.mysql_history as a symbolic to /dev/null.
"""
    reference = '800-53|SC-5,CSF|PR.DS-4,ITSG-33|SC-5,LEVEL|1S'
    see_also = 'https://benchmarks.cisecurity.org/tools2/mysql/CIS_Oracle_MySQL_Community_Server_5.6_Benchmark_v1.1.0.pdf'

    def run(self, config):
        self.set_start_time()
        self.proc = SshTask(config, self.host, "cut -f 6 -d: < /etc/passwd | xargs -I % sudo ls %/.mysql_history 2>/dev/null")
        logging.debug("MySQL 5.6 DedicatedMySQLAccount command was '{}'".format(self.proc.ssh_cmd))
        self.proc.run()

    def poll(self):
        result = self.proc.poll()
        if result is not None:
            self.set_done_time()
        return result

    def finalize(self):
        (self.plugin_output, _) = self.proc.finalize()
        self.plugin_output = self.plugin_output.strip()
        if self.plugin_output.splitlines():
            self.status = DatabaseTest.PASSED
        else:
            self.status = DatabaseTest.FAILED


class BlacklistPasswordEnviron(DatabaseTest):
    benchmark = '1.4'
    risk = DatabaseTest.HIGH
    protocol = 'ssh+mysql'
    port = '40506'
    description_template = '1.4 Verify That the MYSQL_PWD Environment Variables Is Not In Use [{}]'
    info = """The use of the MYSQL_PWD environment variable implies the clear text storage of MySQL
credentials. Avoiding this may increase assurance that the confidentiality of MySQL
credentials is preserved.
"""
    solution = """Check which users and/or scripts are setting MYSQL_PWD and change them to use a more
secure method.
"""
    reference = '800-53|SC-5,CSF|PR.DS-4,ITSG-33|SC-5,LEVEL|1S'
    see_also = 'https://benchmarks.cisecurity.org/tools2/mysql/CIS_Oracle_MySQL_Community_Server_5.6_Benchmark_v1.1.0.pdf'

    def run(self, config):
        # /proc/self/environ and /proc/thread-self/environ end up referring to the grep command itself.
        self.set_start_time()
        self.proc = SshTask(config, self.host, "sudo grep MYSQL_PWD /proc/*/environ --exclude /proc/self/environ --exclude /proc/thread-self/environ")
        logging.debug("MySQL 5.6 DedicatedMySQLAccount command was '{}'".format(self.proc.ssh_cmd))
        self.proc.run()

    def poll(self):
        result = self.proc.poll()
        if result is not None:
            self.set_done_time()
        return result

    def finalize(self):
        (self.plugin_output, _) = self.proc.finalize()
        self.plugin_output = self.plugin_output.strip()
        if self.plugin_output.splitlines():
            self.status = DatabaseTest.FAILED
        else:
            self.status = DatabaseTest.PASSED


class DisableInteractiveLogin(DatabaseTest):
    benchmark = '1.5'
    risk = DatabaseTest.HIGH
    protocol = 'ssh+mysql'
    port = '40506'
    description_template = '1.5 Disable Interactive Login [{}]'
    info = """When created, the MySQL user may have interactive access to the operating system, which
means that the MySQL user could login to the host as any other user would.
"""
    solution = """Perform the following steps to remediate this setting:
• Execute one of the following commands in a terminal
usermod -s /bin/false mysql
usermod -s /sbin/nologin mysql
"""
    reference = '800-53|SC-5,CSF|PR.DS-4,ITSG-33|SC-5,LEVEL|1S'
    see_also = 'https://benchmarks.cisecurity.org/tools2/mysql/CIS_Oracle_MySQL_Community_Server_5.6_Benchmark_v1.1.0.pdf'

    def run(self, config):
        # /proc/self/environ and /proc/thread-self/environ end up referring to the grep command itself.
        self.set_start_time()
        self.proc = SshTask(config, self.host, "getent passwd mysql | cut -f 7 -d :")
        logging.debug("MySQL 5.6 DedicatedMySQLAccount command was '{}'".format(self.proc.ssh_cmd))
        self.proc.run()

    def poll(self):
        result = self.proc.poll()
        if result is not None:
            self.set_done_time()
        return result

    def finalize(self):
        (self.plugin_output, _) = self.proc.finalize()
        self.plugin_output = self.plugin_output.strip()
        lines = self.plugin_output.splitlines()
        if lines:
            if lines[0] == '/bin/false':
                self.status = DatabaseTest.PASSED
                return
        self.status = DatabaseTest.FAILED


class BlacklistPasswordProfiles(DatabaseTest):
    benchmark = '1.6'
    risk = DatabaseTest.HIGH
    protocol = 'ssh+mysql'
    port = '40506'
    description_template = "1.6 Verify That 'MYSQL_PWD' Is Not Set In Users' Profiles [{}]"
    info = """The use of the MYSQL_PWD environment variable implies the clear text storage of MySQL
credentials. Avoiding this may increase assurance that the confidentiality of MySQL
credentials is preserved.
"""
    solution = """Check which users and/or scripts are setting MYSQL_PWD and change them to use a more
secure method.
"""
    reference = '800-53|SC-5,CSF|PR.DS-4,ITSG-33|SC-5,LEVEL|1S'
    see_also = 'https://benchmarks.cisecurity.org/tools2/mysql/CIS_Oracle_MySQL_Community_Server_5.6_Benchmark_v1.1.0.pdf'

    def run(self, config):
        self.set_start_time()
        self.proc = SshTask(config, self.host, "cut -f 6 -d: < /etc/passwd | xargs -L 1 -I % sudo grep MYSQL_PWD %/.profile %/.bashrc %/.bash_profile 2>/dev/null")
        logging.debug("MySQL 5.6 DedicatedMySQLAccount command was '{}'".format(self.proc.ssh_cmd))
        self.proc.run()

    def poll(self):
        result = self.proc.poll()
        if result is not None:
            self.set_done_time()
        return result

    def finalize(self):
        (self.plugin_output, _) = self.proc.finalize()
        self.plugin_output = self.plugin_output.strip()
        if self.plugin_output.splitlines():
            self.status = DatabaseTest.FAILED
        else:
            self.status = DatabaseTest.PASSED


class NoPasswordsCommandLine(DatabaseTest):
    benchmark = '2.3'
    risk = DatabaseTest.HIGH
    protocol = 'ssh+mysql'
    port = '40506'
    description_template = "2.3 Do Not Specify Passwords in Command Line [{}]"
    info = """If the password is visible in the process list or user's shell/command history, an attacker
will be able to access the MySQL database using the stolen credentials.
"""
    solution = """Depending on the remediation chosen, additional steps may need to be undertaken like:
• Entering a password when prompted;
• Ensuring the file permissions on .my.cnf is restricted yet accessible by the user;
• Using mysql_config_editor to encrypt the authentication credentials in
.mylogin.cnf.
Additionally, not all scripts/applications may be able to use .mylogin.cnf.
"""
    reference = '800-53|SC-5,CSF|PR.DS-4,ITSG-33|SC-5,LEVEL|1S'
    see_also = 'https://benchmarks.cisecurity.org/tools2/mysql/CIS_Oracle_MySQL_Community_Server_5.6_Benchmark_v1.1.0.pdf'

    def run(self, config):
        self.set_start_time()
        self.proc = SshTask(config, self.host, "ps -eo command | grep -E '^mysql|^/usr/bin/mysql '")
        logging.debug("MySQL 5.6 DedicatedMySQLAccount command was '{}'".format(self.proc.ssh_cmd))
        self.proc.run()

    def poll(self):
        result = self.proc.poll()
        if result is not None:
            self.set_done_time()
        return result

    def finalize(self):
        (self.plugin_output, _) = self.proc.finalize()
        self.plugin_output = self.plugin_output.strip()
        for line in self.plugin_output.splitlines():
            if re.match(r' -p', line):
                self.status = DatabaseTest.FAILED
                return
        self.status = DatabaseTest.PASSED


class FilePermissionsDatadir(DatabaseTest):
    benchmark = '3.1'
    risk = DatabaseTest.HIGH
    protocol = 'ssh+mysql'
    port = '40506'
    description_template = "3.1 Ensure 'datadir' Has Appropriate Permissions [{}]"
    info = """The SSL certificate and key used by MySQL should be used only for MySQL and only for one instance.
    This test was modified by Acquia."""
    solution = 'Generate a new certificate/key per MySQL instance.'
    reference = '800-53|IA-5,CIP|007-6-R5,PCI-DSSv3.1|2.1,PCI-DSSv3.2|2.1,800-171|3.5.2,CN-L3|7.1.3.2(d),CSF|PR.AC-1,ITSG-33|IA-5,CSCv6|5.3,LEVEL|1NS'
    see_also = 'https://benchmarks.cisecurity.org/tools2/mysql/CIS_Oracle_MySQL_Community_Server_5.6_Benchmark_v1.1.0.pdf'
    description_template = "2.5 Do Not Use Default or Non-MySQL-specific Cryptographic Keys - 'ssl_cert' [{}]"

    def run(self, config):
        self.set_start_time()
        self.proc = SshTask(config, self.host, "ls -ld $(mysql -sNe \"show variables where variable_name = 'datadir';\" | cut -f 2) | awk '{print $1\" \"$3\" \"$4}'")
        logging.debug("MySQL 5.6 UseMySQLUniqueCertificate command was '{}'".format(self.proc.ssh_cmd))
        self.proc.run()

    def poll(self):
        result = self.proc.poll()
        if result is not None:
            self.set_done_time()
        return result

    def finalize(self):
        (self.plugin_output, _) = self.proc.finalize()
        self.plugin_output = self.plugin_output.strip()
        if re.match(r'^drwx------ mysql mysql', self.plugin_output):
            self.status = DatabaseTest.PASSED
        self.status = DatabaseTest.FAILED


class FilePermissionsBinlog(DatabaseTest):
    benchmark = '3.2'
    risk = DatabaseTest.HIGH
    protocol = 'ssh+mysql'
    port = '40506'
    description_template = "3.2 Ensure 'log_bin_basename' Files Have Appropriate Permissions [{}]"
    info = """The SSL certificate and key used by MySQL should be used only for MySQL and only for one instance.
    This test was modified by Acquia."""
    solution = 'Generate a new certificate/key per MySQL instance.'
    reference = '800-53|IA-5,CIP|007-6-R5,PCI-DSSv3.1|2.1,PCI-DSSv3.2|2.1,800-171|3.5.2,CN-L3|7.1.3.2(d),CSF|PR.AC-1,ITSG-33|IA-5,CSCv6|5.3,LEVEL|1NS'
    see_also = 'https://benchmarks.cisecurity.org/tools2/mysql/CIS_Oracle_MySQL_Community_Server_5.6_Benchmark_v1.1.0.pdf'

    def run(self, config):
        self.set_start_time()
        self.proc = SshTask(config, self.host, "sudo bash -c 'ls -l /vol/ebs1/mysql/binlog.*' | awk '{print $1\" \"$3\" \"$4\" \"$9}'")
        logging.debug("MySQL 5.6 UseMySQLUniqueCertificate command was '{}'".format(self.proc.ssh_cmd))
        self.proc.run()

    def poll(self):
        result = self.proc.poll()
        if result is not None:
            self.set_done_time()
        return result

    def finalize(self):
        (self.plugin_output, _) = self.proc.finalize()
        self.plugin_output = self.plugin_output.strip()
        for line in self.plugin_output.splitlines():
            if re.match(r'^-rwxrwx--- mysql mysql', line):
                self.status = DatabaseTest.PASSED
            else:
                self.status = DatabaseTest.FAILED
                return
        if self.status != DatabaseTest.PASSED:
            self.status = DatabaseTest.FAILED


class FilePermissionsErrorLog(DatabaseTest):
    benchmark = '3.3'
    risk = DatabaseTest.HIGH
    protocol = 'ssh+mysql'
    port = '40506'
    description_template = "3.3 Ensure 'log_error' Has Appropriate Permissions [{}]"
    info = """The SSL certificate and key used by MySQL should be used only for MySQL and only for one instance.
    This test was modified by Acquia."""
    solution = 'Generate a new certificate/key per MySQL instance.'
    reference = '800-53|IA-5,CIP|007-6-R5,PCI-DSSv3.1|2.1,PCI-DSSv3.2|2.1,800-171|3.5.2,CN-L3|7.1.3.2(d),CSF|PR.AC-1,ITSG-33|IA-5,CSCv6|5.3,LEVEL|1NS'
    see_also = 'https://benchmarks.cisecurity.org/tools2/mysql/CIS_Oracle_MySQL_Community_Server_5.6_Benchmark_v1.1.0.pdf'

    def run(self, config):
        self.set_start_time()
        self.proc = SshTask(config, self.host, "sudo bash -c 'ls -l /vol/ebs1/mysql/$(hostname).err' | awk '{print $1\" \"$3\" \"$4\" \"$9}'")
        logging.debug("MySQL 5.6 UseMySQLUniqueCertificate command was '{}'".format(self.proc.ssh_cmd))
        self.proc.run()

    def poll(self):
        result = self.proc.poll()
        if result is not None:
            self.set_done_time()
        return result

    def finalize(self):
        (self.plugin_output, _) = self.proc.finalize()
        self.plugin_output = self.plugin_output.strip()
        for line in self.plugin_output.splitlines():
            if re.match(r'^-rwxrwx--- mysql mysql', line):
                self.status = DatabaseTest.PASSED
            else:
                self.status = DatabaseTest.FAILED
                return
        if self.status != DatabaseTest.PASSED:
            self.status = DatabaseTest.FAILED


class FilePermissionsSlowLog(DatabaseTest):
    benchmark = '3.4'
    risk = DatabaseTest.HIGH
    protocol = 'ssh+mysql'
    port = '40506'
    description_template = "3.4 Ensure 'slow_query_log' Has Appropriate Permissions [{}]"
    info = """The SSL certificate and key used by MySQL should be used only for MySQL and only for one instance.
    This test was modified by Acquia."""
    solution = 'Generate a new certificate/key per MySQL instance.'
    reference = '800-53|IA-5,CIP|007-6-R5,PCI-DSSv3.1|2.1,PCI-DSSv3.2|2.1,800-171|3.5.2,CN-L3|7.1.3.2(d),CSF|PR.AC-1,ITSG-33|IA-5,CSCv6|5.3,LEVEL|1NS'
    see_also = 'https://benchmarks.cisecurity.org/tools2/mysql/CIS_Oracle_MySQL_Community_Server_5.6_Benchmark_v1.1.0.pdf'

    def run(self, config):
        self.set_start_time()
        self.proc = SshTask(config, self.host, "sudo bash -c 'ls -l /vol/ebs1/mysql/*-slow.log*' | awk '{print $1\" \"$3\" \"$4\" \"$9}'")
        logging.debug("MySQL 5.6 UseMySQLUniqueCertificate command was '{}'".format(self.proc.ssh_cmd))
        self.proc.run()

    def poll(self):
        result = self.proc.poll()
        if result is not None:
            self.set_done_time()
        return result

    def finalize(self):
        (self.plugin_output, _) = self.proc.finalize()
        self.plugin_output = self.plugin_output.strip()
        for line in self.plugin_output.splitlines():
            if re.match(r'^-rwxrwx--- mysql mysql', line):
                self.status = DatabaseTest.PASSED
            else:
                self.status = DatabaseTest.FAILED
                return
        if self.status != DatabaseTest.PASSED:
            self.status = DatabaseTest.FAILED


class FilePermissionsRelayLog(DatabaseTest):
    benchmark = '3.5'
    risk = DatabaseTest.HIGH
    protocol = 'ssh+mysql'
    port = '40506'
    description_template = "3.5 Ensure 'relay_log_basename' Files Have Appropriate Permissions [{}]"
    info = """The SSL certificate and key used by MySQL should be used only for MySQL and only for one instance.
    This test was modified by Acquia."""
    solution = 'Generate a new certificate/key per MySQL instance.'
    reference = '800-53|IA-5,CIP|007-6-R5,PCI-DSSv3.1|2.1,PCI-DSSv3.2|2.1,800-171|3.5.2,CN-L3|7.1.3.2(d),CSF|PR.AC-1,ITSG-33|IA-5,CSCv6|5.3,LEVEL|1NS'
    see_also = 'https://benchmarks.cisecurity.org/tools2/mysql/CIS_Oracle_MySQL_Community_Server_5.6_Benchmark_v1.1.0.pdf'

    def run(self, config):
        self.set_start_time()
        self.proc = SshTask(config, self.host, "sudo bash -c 'ls -l /vol/ebs1/mysql/relay*' | awk '{print $1\" \"$3\" \"$4\" \"$9}'")
        logging.debug("MySQL 5.6 UseMySQLUniqueCertificate command was '{}'".format(self.proc.ssh_cmd))
        self.proc.run()

    def poll(self):
        result = self.proc.poll()
        if result is not None:
            self.set_done_time()
        return result

    def finalize(self):
        (self.plugin_output, _) = self.proc.finalize()
        self.plugin_output = self.plugin_output.strip()
        for line in self.plugin_output.splitlines():
            if re.match(r'^-rwxrwx--- mysql mysql', line):
                self.status = DatabaseTest.PASSED
            else:
                self.status = DatabaseTest.FAILED
                return


class FilePermissionsGeneralLog(DatabaseTest):
    benchmark = '3.6'
    risk = DatabaseTest.HIGH
    protocol = 'ssh+mysql'
    port = '40506'
    description_template = "3.6 Ensure 'general_log_file' Has Appropriate Permissions [{}]"
    info = """The SSL certificate and key used by MySQL should be used only for MySQL and only for one instance.
    This test was modified by Acquia."""
    solution = 'Generate a new certificate/key per MySQL instance.'
    reference = '800-53|IA-5,CIP|007-6-R5,PCI-DSSv3.1|2.1,PCI-DSSv3.2|2.1,800-171|3.5.2,CN-L3|7.1.3.2(d),CSF|PR.AC-1,ITSG-33|IA-5,CSCv6|5.3,LEVEL|1NS'
    see_also = 'https://benchmarks.cisecurity.org/tools2/mysql/CIS_Oracle_MySQL_Community_Server_5.6_Benchmark_v1.1.0.pdf'

    def run(self, config):
        self.set_start_time()
        self.proc = SshTask(config, self.host, "sudo bash -c 'ls -l /vol/ebs1/mysql/fsdb-62.log' | awk '{print $1\" \"$3\" \"$4\" \"$9}'")
        logging.debug("MySQL 5.6 UseMySQLUniqueCertificate command was '{}'".format(self.proc.ssh_cmd))
        self.proc.run()

    def poll(self):
        result = self.proc.poll()
        if result is not None:
            self.set_done_time()
        return result

    def finalize(self):
        (self.plugin_output, _) = self.proc.finalize()
        self.plugin_output = self.plugin_output.strip()
        for line in self.plugin_output.splitlines():
            if re.match(r'^-rwxrwx--- mysql mysql', line):
                self.status = DatabaseTest.PASSED
            else:
                self.status = DatabaseTest.FAILED
                return


class FilePermissionSSLKey(DatabaseTest):
    benchmark = '3.7'
    risk = DatabaseTest.HIGH
    protocol = 'ssh+mysql'
    port = '40506'
    description_template = "3.6 Ensure 'general_log_file' Has Appropriate Permissions [{}]"
    info = """The SSL certificate and key used by MySQL should be used only for MySQL and only for one instance.
    This test was modified by Acquia."""
    solution = 'Generate a new certificate/key per MySQL instance.'
    reference = '800-53|IA-5,CIP|007-6-R5,PCI-DSSv3.1|2.1,PCI-DSSv3.2|2.1,800-171|3.5.2,CN-L3|7.1.3.2(d),CSF|PR.AC-1,ITSG-33|IA-5,CSCv6|5.3,LEVEL|1NS'
    see_also = 'https://benchmarks.cisecurity.org/tools2/mysql/CIS_Oracle_MySQL_Community_Server_5.6_Benchmark_v1.1.0.pdf'

    def run(self, config):
        self.set_start_time()
        self.proc = SshTask(config, self.host, "sudo bash -c 'ls -l /vol/ebs1/mysql/*.key' | awk '{print $1\" \"$3\" \"$4\" \"$9}'")
        logging.debug("MySQL 5.6 UseMySQLUniqueCertificate command was '{}'".format(self.proc.ssh_cmd))
        self.proc.run()

    def poll(self):
        result = self.proc.poll()
        if result is not None:
            self.set_done_time()
        return result

    def finalize(self):
        (self.plugin_output, _) = self.proc.finalize()
        self.plugin_output = self.plugin_output.strip()
        for line in self.plugin_output.splitlines():
            if re.match(r'^-rwxrwx--- mysql mysql', line):
                self.status = DatabaseTest.PASSED
            else:
                self.status = DatabaseTest.FAILED
                return


class FilePermissionsPluginDir(DatabaseTest):
    benchmark = '3.8'
    risk = DatabaseTest.HIGH
    protocol = 'ssh+mysql'
    port = '40506'
    description_template = "3.8 Ensure Plugin Directory Has Appropriate Permissions [{}]"
    info = """The SSL certificate and key used by MySQL should be used only for MySQL and only for one instance.
    This test was modified by Acquia."""
    solution = 'Generate a new certificate/key per MySQL instance.'
    reference = '800-53|IA-5,CIP|007-6-R5,PCI-DSSv3.1|2.1,PCI-DSSv3.2|2.1,800-171|3.5.2,CN-L3|7.1.3.2(d),CSF|PR.AC-1,ITSG-33|IA-5,CSCv6|5.3,LEVEL|1NS'
    see_also = 'https://benchmarks.cisecurity.org/tools2/mysql/CIS_Oracle_MySQL_Community_Server_5.6_Benchmark_v1.1.0.pdf'

    def run(self, config):
        self.set_start_time()
        self.proc = SshTask(config, self.host, "ls -ld /usr/lib/mysql/plugin/ | awk '{print $1\" \"$3\" \"$4}'")
        logging.debug("MySQL 5.6 UseMySQLUniqueCertificate command was '{}'".format(self.proc.ssh_cmd))
        self.proc.run()

    def poll(self):
        result = self.proc.poll()
        if result is not None:
            self.set_done_time()
        return result

    def finalize(self):
        (self.plugin_output, _) = self.proc.finalize()
        self.plugin_output = self.plugin_output.strip()
        if re.match(r'^drwxr-xr-x mysql mysql', self.plugin_output) or re.match(r'^drwxrwxr-x mysql mysql', self.plugin_output):
            self.status = DatabaseTest.PASSED
        self.status = DatabaseTest.FAILED


class UseMySQLUniqueCertificate(DatabaseTest):
    benchmark = '2.5'
    risk = DatabaseTest.HIGH
    protocol = 'ssh+mysql'
    port = '40506'
    info = """The SSL certificate and key used by MySQL should be used only for MySQL and only for one instance.
    This test was modified by Acquia."""
    solution = 'Generate a new certificate/key per MySQL instance.'
    reference = '800-53|IA-5,CIP|007-6-R5,PCI-DSSv3.1|2.1,PCI-DSSv3.2|2.1,800-171|3.5.2,CN-L3|7.1.3.2(d),CSF|PR.AC-1,ITSG-33|IA-5,CSCv6|5.3,LEVEL|1NS'
    see_also = 'https://benchmarks.cisecurity.org/tools2/mysql/CIS_Oracle_MySQL_Community_Server_5.6_Benchmark_v1.1.0.pdf'
    description_template = "2.5 Do Not Use Default or Non-MySQL-specific Cryptographic Keys - 'ssl_cert' [{}]"

    def run(self, config):
        self.set_start_time()
        self.proc = SshTask(config, self.host, "mysql -s -e \"show variables like 'ssl_cert'\" | tail -n 1")
        logging.debug("MySQL 5.6 UseMySQLUniqueCertificate command was '{}'".format(self.proc.ssh_cmd))
        self.proc.run()

    def poll(self):
        result = self.proc.poll()
        if result is not None:
            self.set_done_time()
        return result

    def finalize(self):
        (self.plugin_output, _) = self.proc.finalize()
        self.plugin_output = self.plugin_output.strip()
        if re.match(r'^ssl_cert', self.plugin_output):
            self.plugin_output = "Failure from lack of ssl_cert parameter being set by MySQL."
            self.status = DatabaseTest.FAILED
        else:
            self.status = DatabaseTest.PASSED


class UseMySQLUniqueKey(DatabaseTest):
    benchmark = '2.5'
    risk = DatabaseTest.HIGH
    protocol = 'ssh+mysql'
    port = '40506'
    info = """The SSL certificate and key used by MySQL should be used only for MySQL and only for one instance.
    This test was modified by Acquia."""
    solution = 'Generate a new certificate/key per MySQL instance.'
    reference = '800-53|IA-5,CIP|007-6-R5,PCI-DSSv3.1|2.1,PCI-DSSv3.2|2.1,800-171|3.5.2,CN-L3|7.1.3.2(d),CSF|PR.AC-1,ITSG-33|IA-5,CSCv6|5.3,LEVEL|1NS'
    see_also = 'https://benchmarks.cisecurity.org/tools2/mysql/CIS_Oracle_MySQL_Community_Server_5.6_Benchmark_v1.1.0.pdf'
    description_template = "2.5 Do Not Use Default or Non-MySQL-specific Cryptographic Keys - 'ssl_key' [{}]"

    def run(self, config):
        self.set_start_time()
        self.proc = SshTask(config, self.host, "mysql -s -e \"show variables like 'ssl_key'\" | tail -n 1")
        logging.debug("MySQL 5.6 UseMySQLUniqueKey command was '{}'".format(self.proc.ssh_cmd))
        self.proc.run()

    def poll(self):
        result = self.proc.poll()
        if result is not None:
            self.set_done_time()
        return result

    def finalize(self):
        (self.plugin_output, _) = self.proc.finalize()
        self.plugin_output = self.plugin_output.strip()
        if re.match(r'^ssl_key', self.plugin_output):
            self.plugin_output = "Failure from lack of ssl_key parameter being set by MySQL."
            self.status = DatabaseTest.FAILED
        else:
            self.status = DatabaseTest.PASSED


class LatestVersion(DatabaseTest):
    benchmark = '4.1'
    risk = DatabaseTest.HIGH
    protocol = 'ssh+mysql'
    port = '40506'
    info = 'Periodically, updates to MySQL server are released to resolve bugs, mitigate vulnerabilities, and provide new features. It is recommended that MySQL installations are up to date with the latest security updates.'
    solution = 'Install the latest patches for your version or upgrade to the latest version.'
    reference = '800-53|SI-2,HIPAA|164.308(a)(5)(ii)(A),800-171|3.14.1,CSF|ID.RA-1,CSF|PR.IP-12,ITSG-33|SI-2,LEVEL|2NS'
    see_also = 'https://benchmarks.cisecurity.org/tools2/mysql/CIS_Oracle_MySQL_Community_Server_5.6_Benchmark_v1.1.0.pdf'
    description_template = '4.1 Ensure Latest Security Patches Are Applied [{}]'

    def run(self, config):
        self.set_start_time()
        self.proc = SshTask(config, self.host, "mysql -s -e 'SELECT VERSION();'")
        logging.debug("LatestVersion command was '{}'".format(self.proc.ssh_cmd))
        self.proc.run()

    def poll(self):
        result = self.proc.poll()
        if result is not None:
            self.set_done_time()
        return result

    def finalize(self):
        (self.plugin_output, _) = self.proc.finalize()
        self.plugin_output = self.plugin_output.strip()
        if re.match(MYSQL_LATEST_VERSION, self.plugin_output):
            self.status = DatabaseTest.PASSED
        else:
            self.plugin_output = "Version mismatch {} did not match pattern {}".format(self.plugin_output, MYSQL_LATEST_VERSION)
            self.status = DatabaseTest.FAILED


class TestDatabaseExists(DatabaseTest):
    benchmark = '4.2'
    risk = DatabaseTest.HIGH
    protocol = 'ssh+mysql'
    port = '40506'
    info = 'The default MySQL installation comes with an unused database called test. It is recommended that the test database be dropped.'
    solution = """Execute the following SQL statement to drop the test database:
   DROP DATABASE 'test';
   Note: mysql_secure_installation performs this operation as well as other security-related activities."""
    reference = '800-53|CM-7,CIP|007-6-R1,PCI-DSSv3.1|2.2.2,PCI-DSSv3.1|2.2.3,PCI-DSSv3.2|2.2.2,PCI-DSSv3.2|2.2.3,800-171|3.4.6,800-171|3.4.7,CN-L3|7.1.3.5(c),CN-L3|7.1.3.7(d),CSF|PR.IP-1,CSF|PR.PT-3,ITSG-33|CM-7,CSCv6|9.1,LEVEL|1S'
    see_also = 'https://benchmarks.cisecurity.org/tools2/mysql/CIS_Oracle_MySQL_Community_Server_5.6_Benchmark_v1.1.0.pdf'
    description_template = "4.2 Ensure the 'test' Database Is Not Installed [{}]"

    def run(self, config):
        self.set_start_time()
        self.proc = SshTask(config, self.host, "mysql -N -B -e \"SELECT SCHEMA_NAME FROM INFORMATION_SCHEMA.SCHEMATA WHERE SCHEMA_NAME = 'test'\"")
        logging.debug("TestDatabaseExists command was '{}'".format(self.proc.ssh_cmd))
        self.proc.run()

    def poll(self):
        result = self.proc.poll()
        if result is not None:
            self.set_done_time()
        return result

    def finalize(self):
        (self.plugin_output, _) = self.proc.finalize()
        self.plugin_output = self.plugin_output.strip()
        if re.match(r'test', self.plugin_output):
            self.status = DatabaseTest.FAILED
        else:
            self.status = DatabaseTest.PASSED


class DisallowSuspiciousUDFs(DatabaseTest):
    benchmark = '4.3'
    risk = DatabaseTest.HIGH
    protocol = 'ssh+mysql'
    port = '40506'
    description_template = "4.3 Ensure 'allow-suspicious-udfs' Is Set to 'FALSE' [{}]"
    info = """It is generally accepted that host operating systems should include different filesystem partitions for different purposes. One set of filesystems are typically called 'system partitions', and are generally reserved for host system/application operation. The other set of filesystems are typically called 'non-system partitions', and such locations are generally reserved for storing data.
"""
    solution = """
Create a user which is only used for running MySQL and directly related processes. This
user must not have administrative rights to the system.
"""
    reference = '800-53|SC-5,CSF|PR.DS-4,ITSG-33|SC-5,LEVEL|1S'
    see_also = 'https://benchmarks.cisecurity.org/tools2/mysql/CIS_Oracle_MySQL_Community_Server_5.6_Benchmark_v1.1.0.pdf'

    def run(self, config):
        self.set_start_time()
        self.proc = SshTask(config, self.host, "ps -eo user,command | grep ^mysql")
        logging.debug("MySQL 5.6 DedicatedMySQLAccount command was '{}'".format(self.proc.ssh_cmd))
        self.proc.run()

    def poll(self):
        result = self.proc.poll()
        if result is not None:
            self.set_done_time()
        return result

    def finalize(self):
        (self.plugin_output, _) = self.proc.finalize()
        self.plugin_output = self.plugin_output.strip()
        for i in self.plugin_output.splitlines():
            if re.match(r'^mysql.*/usr/sbin/mysqld.*--allow-suspicious-udfs', i):
                self.status = DatabaseTest.FAILED
                return
        self.status = DatabaseTest.SUCCESS


class LocalInFileDisabled(DatabaseTest):
    benchmark = '4.4'
    risk = DatabaseTest.HIGH
    protocol = 'ssh+mysql'
    port = '40506'
    info = "The local_infile parameter dictates whether files located on the MySQL client's computer can be loaded or selected via LOAD DATA INFILE or SELECT local_file."
    solution = """Add the following line to the [mysqld] section of the MySQL configuration file and restart the MySQL service:
   local-infile=0"""
    reference = '800-53|CM-7,CIP|007-6-R1,PCI-DSSv3.1|2.2.2,PCI-DSSv3.1|2.2.3,PCI-DSSv3.2|2.2.2,PCI-DSSv3.2|2.2.3,800-171|3.4.6,800-171|3.4.7,CN-L3|7.1.3.5(c),CN-L3|7.1.3.7(d),CSF|PR.IP-1,CSF|PR.PT-3,ITSG-33|CM-7,CSCv6|9.1,LEVEL|1S'
    see_also = 'https://benchmarks.cisecurity.org/tools2/mysql/CIS_Oracle_MySQL_Community_Server_5.6_Benchmark_v1.1.0.pdf'
    description_template = "4.4 Ensure 'local_infile' Is Disabled [{}]"

    def run(self, config):
        self.set_start_time()
        self.proc = SshTask(config, self.host, "mysql -s -e \"show variables like 'local_infile'\" | tail -n 1")
        logging.debug("MySQL 5.6 LocalInFileDisabled command was '{}'".format(self.proc.ssh_cmd))
        self.proc.run()

    def poll(self):
        result = self.proc.poll()
        if result is not None:
            self.set_done_time()
        return result

    def finalize(self):
        (self.plugin_output, _) = self.proc.finalize()
        self.plugin_output = self.plugin_output.strip()
        if re.match(r'^local_infile.ON', self.plugin_output):
            self.plugin_output = "Failure from lack of local_infile parameter being set by MySQL to OFF."
            self.status = DatabaseTest.FAILED
        else:
            self.status = DatabaseTest.PASSED


class CheckSkipGrantTables(DatabaseTest):
    benchmark = '4.5'
    risk = DatabaseTest.HIGH
    protocol = 'ssh+mysql'
    port = '40506'
    description_template = "4.5 Ensure 'mysqld' Is Not Started with '--skip-grant-tables' [{}]"
    info = """It is generally accepted that host operating systems should include different filesystem partitions for different purposes. One set of filesystems are typically called 'system partitions', and are generally reserved for host system/application operation. The other set of filesystems are typically called 'non-system partitions', and such locations are generally reserved for storing data.
"""
    solution = """
Create a user which is only used for running MySQL and directly related processes. This
user must not have administrative rights to the system.
"""
    reference = '800-53|SC-5,CSF|PR.DS-4,ITSG-33|SC-5,LEVEL|1S'
    see_also = 'https://benchmarks.cisecurity.org/tools2/mysql/CIS_Oracle_MySQL_Community_Server_5.6_Benchmark_v1.1.0.pdf'

    def run(self, config):
        self.set_start_time()
        self.proc = SshTask(config, self.host, "ps -eo user,command | grep ^mysql")
        logging.debug("MySQL 5.6 DedicatedMySQLAccount command was '{}'".format(self.proc.ssh_cmd))
        self.proc.run()

    def poll(self):
        result = self.proc.poll()
        if result is not None:
            self.set_done_time()
        return result

    def finalize(self):
        (self.plugin_output, _) = self.proc.finalize()
        self.plugin_output = self.plugin_output.strip()
        for i in self.plugin_output.splitlines():
            if re.match(r'^mysql.*/usr/sbin/mysqld.*--skip-grant-tables', i):
                self.status = DatabaseTest.FAILED
                return
        self.status = DatabaseTest.SUCCESS


class SkipSymbolicLinksTest(DatabaseTest):
    benchmark = '4.6'
    risk = DatabaseTest.HIGH
    protocol = 'ssh+mysql'
    port = '40506'
    info = "The symbolic-links and skip-symbolic-links options for MySQL determine whether symbolic link support is available. When use of symbolic links are enabled, they have different effects depending on the host platform. When symbolic links are disabled, then symbolic links stored in files or entries in tables are not used by the database."
    solution = """Perform the following actions to remediate this setting:
   - Open the MySQL configuration file (my.cnf)
   - Locate skip_symbolic_links in the configuration
   - Set the skip_symbolic_links to YES
   NOTE: If skip_symbolic_links does not exist, add it to the configuration file in the mysqld section."""
    reference = '800-53|CM-6,PCI-DSSv3.1|2.2.4,PCI-DSSv3.2|2.2.4,800-171|3.4.2,CSF|PR.IP-1,ITSG-33|CM-6,CSCv6|3.1,LEVEL|1S'
    see_also = 'https://benchmarks.cisecurity.org/tools2/mysql/CIS_Oracle_MySQL_Community_Server_5.6_Benchmark_v1.1.0.pdf'
    description_template = "4.6 Ensure '-skip-symbolic-links' Is Enabled [{}]"

    def run(self, config):
        self.set_start_time()
        self.proc = SshTask(config, self.host, "mysql -s -e \"show variables like 'have_symlink'\" | tail -n 1")
        logging.debug("MySQL 5.6 SkipSymbolicLinksTest command was '{}'".format(self.proc.ssh_cmd))
        self.proc.run()

    def poll(self):
        result = self.proc.poll()
        if result is not None:
            self.set_done_time()
        return result

    def finalize(self):
        (self.plugin_output, _) = self.proc.finalize()
        self.plugin_output = self.plugin_output.strip()
        if re.match(r'^have_symlink.ENABLED', self.plugin_output):
            self.plugin_output = "Failure from lack of have_symlink parameter being set by MySQL to OFF."
            self.status = DatabaseTest.FAILED
        else:
            self.status = DatabaseTest.PASSED


class MemcacheDisabled(DatabaseTest):
    benchmark = '4.7'
    risk = DatabaseTest.HIGH
    protocol = 'ssh+mysql'
    port = '40506'
    info = "The InnoDB memcached Plugin allows users to access data stored in InnoDB with the memcached protocol."
    solution = """To remediate this setting, issue the following command in the MySQL command-line client:
   uninstall plugin daemon_memcached;
   This uninstalls the memcached plugin from the MySQL server."""
    reference = '800-53|CM-7,CIP|007-6-R1,PCI-DSSv3.1|2.2.2,PCI-DSSv3.1|2.2.3,PCI-DSSv3.2|2.2.2,PCI-DSSv3.2|2.2.3,800-171|3.4.6,800-171|3.4.7,CN-L3|7.1.3.5(c),CN-L3|7.1.3.7(d),CSF|PR.IP-1,CSF|PR.PT-3,ITSG-33|CM-7,CSCv6|9.1,LEVEL|1S'
    see_also = 'https://benchmarks.cisecurity.org/tools2/mysql/CIS_Oracle_MySQL_Community_Server_5.6_Benchmark_v1.1.0.pdf'
    description_template = "4.7 Ensure the 'daemon_memcached' Plugin Is Disabled [{}]"

    def run(self, config):
        self.set_start_time()
        self.proc = SshTask(config, self.host, "mysql -s -e \"SELECT PLUGIN_NAME, PLUGIN_STATUS FROM information_schema.plugins WHERE PLUGIN_NAME='daemon_memcached'\"")
        logging.debug("MySQL 5.6 SkipSymbolicLinksTest command was '{}'".format(self.proc.ssh_cmd))
        self.proc.run()

    def poll(self):
        result = self.proc.poll()
        if result is not None:
            self.set_done_time()
        return result

    def finalize(self):
        (self.plugin_output, _) = self.proc.finalize()
        self.plugin_output = self.plugin_output.strip()
        if re.match(r'^daemon_memcached', self.plugin_output):
            self.status = DatabaseTest.FAILED
        else:
            self.status = DatabaseTest.PASSED


class SecureFilePriv(DatabaseTest):
    benchmark = '4.8'
    risk = DatabaseTest.HIGH
    protocol = 'ssh+mysql'
    port = '40506'
    info = "The secure_file_priv option restricts to paths used by LOAD DATA INFILE or SELECT local_file. It is recommended that this option be set to a file system location that contains only resources expected to be loaded by MySQL."
    solution = """Add the following line to the [mysqld] section of the MySQL configuration file and restart the MySQL service:
   secure_file_priv=<path_to_load_directory>"""
    reference = '800-53|CM-6,PCI-DSSv3.1|2.2.4,PCI-DSSv3.2|2.2.4,800-171|3.4.2,CSF|PR.IP-1,ITSG-33|CM-6,CSCv6|3.1,LEVEL|1S'
    see_also = 'https://benchmarks.cisecurity.org/tools2/mysql/CIS_Oracle_MySQL_Community_Server_5.6_Benchmark_v1.1.0.pdf'
    description_template = "4.8 Ensure 'secure_file_priv' Is Not Empty [{}]"

    def run(self, config):
        self.set_start_time()
        self.proc = SshTask(config, self.host, "mysql -s -e \"SHOW GLOBAL VARIABLES WHERE Variable_name = 'secure_file_priv' AND Value<>''\"")
        logging.debug("MySQL 5.6 SecureFilePriv command was '{}'".format(self.proc.ssh_cmd))
        self.proc.run()

    def poll(self):
        result = self.proc.poll()
        if result is not None:
            self.set_done_time()
        return result

    def finalize(self):
        (self.plugin_output, _) = self.proc.finalize()
        self.plugin_output = self.plugin_output.strip()
        if re.match(r'^secure_file_priv', self.plugin_output):
            self.status = DatabaseTest.PASSED
        else:
            self.status = DatabaseTest.FAILED


class SQLModeStrictAllTables(DatabaseTest):
    benchmark = '4.9'
    risk = DatabaseTest.HIGH
    protocol = 'ssh+mysql'
    port = '40506'
    description_template = "4.9 Ensure 'sql_mode' Contains 'STRICT_ALL_TABLES' [{}]"
    info = "NO_AUTO_CREATE_USER is an option for sql_mode that prevents a GRANT statement from automatically creating a user when authentication information is not provided."
    solution = """Perform the following actions to remediate this setting:
   1. Open the MySQL configuration file (my.cnf)
   2. Find the sql_mode setting in the [mysqld] area
   3. Add the NO_AUTO_CREATE_USER to the sql_mode setting"""
    reference = '800-53|AC-6,PCI-DSSv3.1|7.1.2,PCI-DSSv3.2|7.1.2,800-171|3.1.5,CN-L3|7.1.3.2(b),CN-L3|7.1.3.2(g),CSF|PR.AC-4,CSF|PR.DS-5,ITSG-33|AC-6,LEVEL|1S'
    see_also = 'https://benchmarks.cisecurity.org/tools2/mysql/CIS_Oracle_MySQL_Community_Server_5.6_Benchmark_v1.1.0.pdf'

    def run(self, config):
        self.set_start_time()
        self.proc = SshTask(config, self.host, "mysql -s -e \"show variables like 'sql_mode'\"")
        logging.debug("MySQL 5.6 NoAutoCreateUser command was '{}'".format(self.proc.ssh_cmd))
        self.proc.run()

    def poll(self):
        result = self.proc.poll()
        if result is not None:
            self.set_done_time()
        return result

    def finalize(self):
        (self.plugin_output, _) = self.proc.finalize()
        self.plugin_output = self.plugin_output.strip()
        if re.match(r'STRICT_ALL_TABLES', self.plugin_output):
            self.status = DatabaseTest.PASSED
        else:
            self.plugin_output = self.plugin_output + "\nExpected STRICT_ALL_TABLES."
            self.status = DatabaseTest.FAILED


class MySQLUserTableDML_ACL(DatabaseTest):
    benchmark = '5.1'
    risk = DatabaseTest.HIGH
    protocol = 'ssh+mysql'
    port = '40506'
    info = "The mysql.user and mysql.db tables list a variety of privileges that can be granted (or denied) to MySQL users. Some of the privileges of concern include: Select_priv, Insert_priv, Update_priv, Delete_priv, Drop_priv, and so on. Typically, these privileges should not be available to every MySQL user and often are reserved for administrative use only."
    solution = "Perform the following actions to remediate this setting: 1. Enumerate non-administrative users resulting from the audit procedure 2. For each non-administrative user, use the REVOKE statement to remove privileges as appropriate"
    reference = 'LEVEL|1S'
    see_also = 'https://benchmarks.cisecurity.org/tools2/mysql/CIS_Oracle_MySQL_Community_Server_5.6_Benchmark_v1.1.0.pdf'
    description_template = "5.1 Ensure Only Administrative Users Have Full Database Access 'mysql.user' [{}]"

    def run(self, config):
        self.set_start_time()
        self.proc = SshTask(config, self.host, "mysql -NB -e \"SELECT user, host FROM mysql.user WHERE (Select_priv = 'Y') OR (Insert_priv = 'Y') OR (Update_priv = 'Y') OR (Delete_priv = 'Y') OR (Create_priv = 'Y') OR (Drop_priv = 'Y') ORDER BY user,host;\"")
        logging.debug("MySQL 5.6 MySQLUserTableDML_ACL command was '{}'".format(self.proc.ssh_cmd))
        self.proc.run()

    def poll(self):
        result = self.proc.poll()
        if result is not None:
            self.set_done_time()
        return result

    def finalize(self):
        (self.plugin_output, _) = self.proc.finalize()
        ok = ["root\t127.0.0.1",
              "root\t::1",
              "root\t"+self.host,
              "root\tlocalhost"]
        arr = self.plugin_output.splitlines()
        test = True
        for i in range(0, len(arr)):
            for s in ok:
                if arr[i] == s:
                    arr[i] = arr[i] + " - MATCH"
                    next
            if " - MATCH" not in arr[i]:
                test = False
        if test:
            self.status = DatabaseTest.PASSED
        else:
            self.plugin_output = "\n".join(arr)
            self.status = DatabaseTest.FAILED


class MySQLDBTableDML_ACL(DatabaseTest):
    # this is ok for cis-scanner to have SELECT ONLY access so we can
    # detect the problem.
    benchmark = '5.1'
    risk = DatabaseTest.HIGH
    protocol = 'ssh+mysql'
    port = '40506'
    info = "The mysql.user and mysql.db tables list a variety of privileges that can be granted (or denied) to MySQL users. Some of the privileges of concern include: Select_priv, Insert_priv, Update_priv, Delete_priv, Drop_priv, and so on. Typically, these privileges should not be available to every MySQL user and often are reserved for administrative use only."
    solution = "Perform the following actions to remediate this setting: 1. Enumerate non-administrative users resulting from the audit procedure 2. For each non-administrative user, use the REVOKE statement to remove privileges as appropriate"
    reference = 'LEVEL|1S'
    see_also = 'https://benchmarks.cisecurity.org/tools2/mysql/CIS_Oracle_MySQL_Community_Server_5.6_Benchmark_v1.1.0.pdf'
    description_template = "5.1 Ensure Only Administrative Users Have Full Database Access 'mysql.db' [{}]"

    def run(self, config):
        self.set_start_time()
        self.proc = SshTask(config, self.host, "mysql -NB -e \"SELECT user, host FROM mysql.db WHERE db = 'mysql' AND ((Select_priv = 'Y') OR (Insert_priv = 'Y') OR (Update_priv = 'Y') OR (Delete_priv = 'Y') OR (Create_priv = 'Y') OR (Drop_priv = 'Y'))\"")
        logging.debug("MySQL 5.6 MySQLDBTableDML_ACL command was '{}'".format(self.proc.ssh_cmd))
        self.proc.run()

    def poll(self):
        result = self.proc.poll()
        if result is not None:
            self.set_done_time()
        return result

    def finalize(self):
        (self.plugin_output, _) = self.proc.finalize()
        ok = ["cis-scanner\tlocalhost"]
        arr = self.plugin_output.splitlines()
        test = True
        for i in range(0, len(arr)):
            for s in ok:
                if arr[i] == s:
                    arr[i] = arr[i] + " - MATCH"
                    next
            if " - MATCH" not in arr[i]:
                test = False
        if test:
            self.status = DatabaseTest.PASSED
        else:
            self.plugin_output = "\n".join(arr)
            self.status = DatabaseTest.FAILED


class FilePrivTest(DatabaseTest):
    benchmark = '5.2'
    risk = DatabaseTest.HIGH
    protocol = 'ssh+mysql'
    port = '40506'
    info = """The File_priv privilege found in the mysql.user table is used to allow or disallow a user from reading and writing files on the server host. Any user with the File_priv right granted has the ability to:
   - Read files from the local file system that are readable by the MySQL server (this includes world-readable files)
   - Write files to the local file system where the MySQL server has write access"""
    solution = """Perform the following steps to remediate this setting:
   1. Enumerate the non-administrative users found in the result set of the audit procedure
   2. For each user, issue the following SQL statement (replace '<user>' with the non- administrative user:

   REVOKE FILE ON *.* FROM '<user>';"""
    reference = '800-53|AC-6,800-171|3.1.5,CSF|PR.AC-4,ISO/IEC-27001|A.9.2.3,ITSG-33|AC-6,CSCv6|5.1,LEVEL|1NS'
    see_also = 'https://benchmarks.cisecurity.org/tools2/mysql/CIS_Oracle_MySQL_Community_Server_5.6_Benchmark_v1.1.0.pdf'
    description_template = "5.2 Ensure 'file_priv' Is Not Set to 'Y' for Non-Administrative Users [{}]"

    def run(self, config):
        self.set_start_time()
        self.proc = SshTask(config, self.host, "mysql -NB -e \"select user, host from mysql.user where File_priv = 'Y' ;\"")
        logging.debug("MySQL 5.6 FilePrivTest command was '{}'".format(self.proc.ssh_cmd))
        self.proc.run()

    def poll(self):
        result = self.proc.poll()
        if result is not None:
            self.set_done_time()
        return result

    def finalize(self):
        (self.plugin_output, _) = self.proc.finalize()
        ok = ["root\tlocalhost"]
        arr = self.plugin_output.splitlines()
        test = True
        for i in range(0, len(arr)):
            for s in ok:
                if arr[i] == s:
                    arr[i] = arr[i] + " - MATCH"
                    next
            if " - MATCH" not in arr[i]:
                test = False
        if test:
            self.status = DatabaseTest.PASSED
        else:
            self.plugin_output = "\n".join(arr)
            self.status = DatabaseTest.FAILED


class ProcPrivTest(DatabaseTest):
    benchmark = '5.3'
    risk = DatabaseTest.HIGH
    protocol = 'ssh+mysql'
    port = '40506'
    info = """The File_priv privilege found in the mysql.user table is used to allow or disallow a user from reading and writing files on the server host. Any user with the File_priv right granted has the ability to:
   - Read files from the local file system that are readable by the MySQL server (this includes world-readable files)
   - Write files to the local file system where the MySQL server has write access"""
    solution = """Perform the following steps to remediate this setting:
   1. Enumerate the non-administrative users found in the result set of the audit procedure
   2. For each user, issue the following SQL statement (replace '<user>' with the non- administrative user:

   REVOKE FILE ON *.* FROM '<user>';"""
    reference = '800-53|AC-6,800-171|3.1.5,CSF|PR.AC-4,ISO/IEC-27001|A.9.2.3,ITSG-33|AC-6,CSCv6|5.1,LEVEL|1NS'
    see_also = 'https://benchmarks.cisecurity.org/tools2/mysql/CIS_Oracle_MySQL_Community_Server_5.6_Benchmark_v1.1.0.pdf'
    description_template = "5.3 Ensure 'process_priv' Is Not Set to 'Y' for Non-Administrative Users [{}]"

    def run(self, config):
        self.set_start_time()
        self.proc = SshTask(config, self.host, "mysql -NB -e \"select user, host from mysql.user where Process_priv = 'Y' ;\"")
        logging.debug("MySQL 5.6 FilePrivTest command was '{}'".format(self.proc.ssh_cmd))
        self.proc.run()

    def poll(self):
        result = self.proc.poll()
        if result is not None:
            self.set_done_time()
        return result

    def finalize(self):
        (self.plugin_output, _) = self.proc.finalize()
        ok = ["root\tlocalhost"]
        arr = self.plugin_output.splitlines()
        test = True
        for i in range(0, len(arr)):
            for s in ok:
                if arr[i] == s:
                    arr[i] = arr[i] + " - MATCH"
                    next
            if " - MATCH" not in arr[i]:
                test = False
        if test:
            self.status = DatabaseTest.PASSED
        else:
            self.plugin_output = "\n".join(arr)
            self.status = DatabaseTest.FAILED


class SuperPrivTest(DatabaseTest):
    benchmark = '5.4'
    risk = DatabaseTest.HIGH
    protocol = 'ssh+mysql'
    port = '40506'
    info = "The SUPER privilege found in the mysql.user table governs the use of a variety of MySQL features. These features include, CHANGE MASTER TO, KILL, mysqladmin kill option, PURGE BINARY LOGS, SET GLOBAL, mysqladmin debug option, logging control, and more."
    solution = """Perform the following steps to remediate this setting:
   1. Enumerate the non-administrative users found in the result set of the audit procedure
   2. For each user, issue the following SQL statement (replace '<user>' with the non- administrative user:

   REVOKE SUPER ON *.* FROM '<user>';"""
    reference = '800-53|AC-6,800-171|3.1.5,CSF|PR.AC-4,ISO/IEC-27001|A.9.2.3,ITSG-33|AC-6,CSCv6|5.1,LEVEL|1S'
    see_also = 'https://benchmarks.cisecurity.org/tools2/mysql/CIS_Oracle_MySQL_Community_Server_5.6_Benchmark_v1.1.0.pdf'
    description_template = "5.4 Ensure 'super_priv' Is Not Set to 'Y' for Non-Administrative Users [{}]"

    def run(self, config):
        self.set_start_time()
        self.proc = SshTask(config, self.host, "mysql -NB -e \"select user, host from mysql.user where Super_priv = 'Y'\"")
        logging.debug("MySQL 5.6 SuperPrivTest command was '{}'".format(self.proc.ssh_cmd))
        self.proc.run()

    def poll(self):
        result = self.proc.poll()
        if result is not None:
            self.set_done_time()
        return result

    def finalize(self):
        (self.plugin_output, _) = self.proc.finalize()
        ok = ["root\tlocalhost",
              "root\t127.0.0.1",
              "root\t::1",
              "root\t"+self.host]
        arr = self.plugin_output.splitlines()
        test = True
        for i in range(0, len(arr)):
            for s in ok:
                if arr[i] == s:
                    arr[i] = arr[i] + " - MATCH"
                    next
            if " - MATCH" not in arr[i]:
                test = False
        if test:
            self.status = DatabaseTest.PASSED
        else:
            self.plugin_output = "\n".join(arr)
            self.status = DatabaseTest.FAILED


class ShutdownPrivTest(DatabaseTest):
    # if the debian-sys-maint user is the package user, shutdown is an
    # appropriate priv.
    benchmark = '5.5'
    risk = DatabaseTest.HIGH
    protocol = 'ssh+mysql'
    port = '40506'
    info = "The SHUTDOWN privilege simply enables use of the shutdown option to the mysqladmin command, which allows a user with the SHUTDOWN privilege the ability to shut down the MySQL server."
    solution = """Perform the following steps to remediate this setting:
   1. Enumerate the non-administrative users found in the result set of the audit procedure
   2. For each user, issue the following SQL statement (replace '<user>' with the non- administrative user):

   REVOKE SHUTDOWN ON *.* FROM '<user>';"""
    reference = '800-53|AC-6,800-171|3.1.5,CSF|PR.AC-4,ISO/IEC-27001|A.9.2.3,ITSG-33|AC-6,CSCv6|5.1,LEVEL|1S'
    see_also = 'https://benchmarks.cisecurity.org/tools2/mysql/CIS_Oracle_MySQL_Community_Server_5.6_Benchmark_v1.1.0.pdf'
    description_template = "5.5 Ensure 'shutdown_priv' Is Not Set to 'Y' for Non-Administrative Users [{}]"

    def run(self, config):
        self.set_start_time()
        self.proc = SshTask(config, self.host, "mysql -NB -e \"select user, host from mysql.user where Shutdown_priv = 'Y'\"")
        logging.debug("MySQL 5.6 Shutdown command was '{}'".format(self.proc.ssh_cmd))
        self.proc.run()

    def poll(self):
        result = self.proc.poll()
        if result is not None:
            self.set_done_time()
        return result

    def finalize(self):
        (self.plugin_output, _) = self.proc.finalize()
        ok = ["root\tlocalhost",
              "root\t127.0.0.1",
              "root\t::1",
              "root\t"+self.host,
              "debian-sys-maint\tlocalhost"]
        arr = self.plugin_output.splitlines()
        test = True
        for i in range(0, len(arr)):
            for s in ok:
                if arr[i] == s:
                    arr[i] = arr[i] + " - MATCH"
                    next
            if " - MATCH" not in arr[i]:
                test = False
        if test:
            self.status = DatabaseTest.PASSED
        else:
            self.plugin_output = "\n".join(arr)
            self.status = DatabaseTest.FAILED


class CreateUserPrivTest(DatabaseTest):
    benchmark = '5.6'
    risk = DatabaseTest.HIGH
    protocol = 'ssh+mysql'
    port = '40506'
    info = "The CREATE USER privilege governs the right of a given user to add or remove users, change existing users' names, or revoke existing users' privileges."
    solution = """Perform the following steps to remediate this setting:
   1. Enumerate the non-administrative users found in the result set of the audit procedure
   2. For each user, issue the following SQL statement (replace '<user>' with the non- administrative user):

   REVOKE CREATE USER ON *.* FROM '<user>';"""
    reference = '800-53|AC-6,800-171|3.1.5,CSF|PR.AC-4,ISO/IEC-27001|A.9.2.3,ITSG-33|AC-6,CSCv6|5.1,LEVEL|1S'
    see_also = 'https://benchmarks.cisecurity.org/tools2/mysql/CIS_Oracle_MySQL_Community_Server_5.6_Benchmark_v1.1.0.pdf'
    description_template = "5.6 Ensure 'create_user_priv' Is Not Set to 'Y' for Non-Administrative Users [{}]"

    def run(self, config):
        self.set_start_time()
        self.proc = SshTask(config, self.host, "mysql -NB -e \"select user, host from mysql.user where Create_user_priv = 'Y'\"")
        logging.debug("MySQL 5.6 Shutdown command was '{}'".format(self.proc.ssh_cmd))
        self.proc.run()

    def poll(self):
        result = self.proc.poll()
        if result is not None:
            self.set_done_time()
        return result

    def finalize(self):
        (self.plugin_output, _) = self.proc.finalize()
        ok = ["root\tlocalhost",
              "root\t127.0.0.1",
              "root\t::1",
              "root\t"+self.host]
        arr = self.plugin_output.splitlines()
        test = True
        for i in range(0, len(arr)):
            for s in ok:
                if arr[i] == s:
                    arr[i] = arr[i] + " - MATCH"
                    next
            if " - MATCH" not in arr[i]:
                test = False
        if test:
            self.status = DatabaseTest.PASSED
        else:
            self.plugin_output = "\n".join(arr)
            self.status = DatabaseTest.FAILED


class GrantPrivTest(DatabaseTest):
    benchmark = '5.7'
    risk = DatabaseTest.HIGH
    protocol = 'ssh+mysql'
    port = '40506'
    info = "The GRANT OPTION privilege exists in different contexts (mysql.user, mysql.db) for the purpose of governing the ability of a privileged user to manipulate the privileges of other users."
    solution = """Perform the following steps to remediate this setting:
   1. Enumerate the non-administrative users found in the result sets of the audit procedure
   2. For each user, issue the following SQL statement (replace '<user>' with the non- administrative user:

   REVOKE GRANT OPTION ON *.* FROM <user>;"""
    reference = '800-53|AC-6,800-171|3.1.5,CSF|PR.AC-4,ISO/IEC-27001|A.9.2.3,ITSG-33|AC-6,CSCv6|5.1,LEVEL|1S'
    see_also = 'https://benchmarks.cisecurity.org/tools2/mysql/CIS_Oracle_MySQL_Community_Server_5.6_Benchmark_v1.1.0.pdf'
    description_template = "5.7 Ensure 'grant_priv' Is Not Set to 'Y' for Non-Administrative Users 'mysql.user' [{}]"

    def run(self, config):
        self.set_start_time()
        self.proc = SshTask(config, self.host, "mysql -NB -e \"select user, host from mysql.user where Grant_priv = 'Y'\"")
        logging.debug("MySQL 5.6 GrantPrivTest command was '{}'".format(self.proc.ssh_cmd))
        self.proc.run()

    def poll(self):
        result = self.proc.poll()
        if result is not None:
            self.set_done_time()
        return result

    def finalize(self):
        (self.plugin_output, _) = self.proc.finalize()
        ok = ["root\tlocalhost",
              "root\t127.0.0.1",
              "root\t::1",
              "root\t"+self.host]
        arr = self.plugin_output.splitlines()
        test = True
        for i in range(0, len(arr)):
            for s in ok:
                if arr[i] == s:
                    arr[i] = arr[i] + " - MATCH"
                    next
            if " - MATCH" not in arr[i]:
                test = False
        if test:
            self.status = DatabaseTest.PASSED
        else:
            self.plugin_output = "\n".join(arr)
            self.status = DatabaseTest.FAILED


class ReplSlavePrivTest(DatabaseTest):
    benchmark = '5.8'
    risk = DatabaseTest.HIGH
    protocol = 'ssh+mysql'
    port = '40506'
    info = "The REPLICATION SLAVE privilege governs whether a given user (in the context of the master server) can request updates that have been made on the master server."
    solution = """Perform the following steps to remediate this setting:
   1. Enumerate the non-slave users found in the result set of the audit procedure
   2. For each user, issue the following SQL statement (replace '<user>' with the non- slave user):

   REVOKE REPLICATION SLAVE ON *.* FROM <user>;"""
    reference = '800-53|AC-6,800-171|3.1.5,CSF|PR.AC-4,ISO/IEC-27001|A.9.2.3,ITSG-33|AC-6,CSCv6|5.1,LEVEL|1S'
    see_also = 'https://benchmarks.cisecurity.org/tools2/mysql/CIS_Oracle_MySQL_Community_Server_5.6_Benchmark_v1.1.0.pdf'
    description_template = "5.8 Ensure 'repl_slave_priv' Is Not Set to 'Y' for Non-Slave Users [{}]"

    def run(self, config):
        self.set_start_time()
        self.proc = SshTask(config, self.host, "mysql -NB -e \"select user, host from mysql.user where Repl_slave_priv = 'Y'\"")
        logging.debug("MySQL 5.6 GrantPrivTest command was '{}'".format(self.proc.ssh_cmd))
        self.proc.run()

    def poll(self):
        result = self.proc.poll()
        if result is not None:
            self.set_done_time()
        return result

    def finalize(self):
        (self.plugin_output, _) = self.proc.finalize()
        ok = ["root\tlocalhost",
              "root\t127.0.0.1",
              "root\t::1",
              "root\t"+self.host]
        arr = self.plugin_output.splitlines()
        test = True
        for i in range(0, len(arr)):
            for s in ok:
                if arr[i] == s:
                    arr[i] = arr[i] + " - MATCH"
                    next
            if " - MATCH" not in arr[i]:
                test = False
        if test:
            self.status = DatabaseTest.PASSED
        else:
            self.plugin_output = "\n".join(arr)
            self.status = DatabaseTest.FAILED


class SpecificGrantCheck(DatabaseTest):
    benchmark = '5.9'
    risk = DatabaseTest.HIGH
    protocol = 'ssh+mysql'
    port = '40506'
    info = "DML/DDL includes the set of privileges used to modify or create data structures. This includes INSERT, SELECT, UPDATE, DELETE, DROP, CREATE, and ALTER privileges."
    solution = """Perform the following steps to remediate this setting:
   1. Enumerate the unauthorized users, hosts, and databases returned in the result set of the audit procedure
   2. For each user, issue the following SQL statement (replace '<user>' with the unauthorized user, '<host>' with host name, and '<database>' with the database name):

   REVOKE SELECT ON <host>.<database> FROM <user>;
   REVOKE INSERT ON <host>.<database> FROM <user>;
   REVOKE UPDATE ON <host>.<database> FROM <user>;
   REVOKE DELETE ON <host>.<database> FROM <user>;
   REVOKE CREATE ON <host>.<database> FROM <user>;
   REVOKE DROP ON <host>.<database> FROM <user>;
   REVOKE ALTER ON <host>.<database> FROM <user>;"""
    reference = '800-53|AC-6,800-171|3.1.5,CSF|PR.AC-4,ISO/IEC-27001|A.9.2.3,ITSG-33|AC-6,CSCv6|5.1,LEVEL|1S'
    see_also = 'https://benchmarks.cisecurity.org/tools2/mysql/CIS_Oracle_MySQL_Community_Server_5.6_Benchmark_v1.1.0.pdf'
    description_template = "5.9 Ensure DML/DDL Grants Are Limited to Specific Databases and Users [{}]"

    def run(self, config):
        self.set_start_time()
        self.proc = SshTask(config, self.host, "mysql -NB -e \"SELECT User,Host,Db FROM mysql.db WHERE Select_priv='Y' OR Insert_priv='Y' OR Update_priv='Y' OR Delete_priv='Y' OR Create_priv='Y' OR Drop_priv='Y' OR Alter_priv='Y'\"")
        logging.debug("MySQL 5.6 SpecificGrantCheck command was '{}'".format(self.proc.ssh_cmd))
        self.proc.run()

    def poll(self):
        result = self.proc.poll()
        if result is not None:
            self.set_done_time()
        return result

    def finalize(self):
        (self.plugin_output, _) = self.proc.finalize()
        arr = self.plugin_output.splitlines()
        test = True
        for i in range(0, len(arr)):
            record = arr[i].split('\t')
            if record[0] == '' or record[1] == '' or record[2] == '':
                arr[i] = arr[i] + ' - FAIL'
                test = False

        if test:
            self.status = DatabaseTest.PASSED
        else:
            self.plugin_output = "\n".join(arr)
            self.status = DatabaseTest.FAILED


class LogErrorTest(DatabaseTest):
    benchmark = '6.1'
    risk = DatabaseTest.HIGH
    protocol = 'ssh+mysql'
    port = '40506'
    info = "The error log contains information about events such as mysqld starting and stopping, when a table needs to be checked or repaired, and, depending on the host operating system, stack traces when mysqld fails."
    solution = """Perform the following actions to remediate this setting:
   1. Open the MySQL configuration file (my.cnf or my.ini)
   2. Set the log-error option to the path for the error log"""
    reference = '800-53|AU-12,800-171|3.3.1,800-171|3.3.2,CN-L3|7.1.3.3(a),CN-L3|7.1.3.3(b),CN-L3|7.1.3.3(c),CSF|DE.CM-1,CSF|DE.CM-3,CSF|DE.CM-7,CSF|PR.PT-1,ISO/IEC-27001|A.12.4.1,ITSG-33|AU-12,TBA-FIISB|45.1.1,LEVEL|1S'
    see_also = 'https://benchmarks.cisecurity.org/tools2/mysql/CIS_Oracle_MySQL_Community_Server_5.6_Benchmark_v1.1.0.pdf'
    description_template = "6.1 Ensure 'log_error' Is Not Empty [{}]"

    def run(self, config):
        self.set_start_time()
        self.proc = SshTask(config, self.host, "mysql -s -e \"show variables like 'log_error'\" | tail -n 1")
        logging.debug("MySQL 5.6 LogErrorTest command was '{}'".format(self.proc.ssh_cmd))
        self.proc.run()

    def poll(self):
        result = self.proc.poll()
        if result is not None:
            self.set_done_time()
        return result

    def finalize(self):
        (self.plugin_output, _) = self.proc.finalize()
        self.plugin_output = self.plugin_output.strip()
        if re.match(r'^log_error./var', self.plugin_output):
            self.status = DatabaseTest.PASSED
        else:
            self.plugin_output = "Failure from lack of log_error parameter being set by MySQL to OFF."
            self.status = DatabaseTest.FAILED


class LogsPartition(DatabaseTest):
    benchmark = '6.2'
    risk = DatabaseTest.HIGH
    protocol = 'ssh+mysql'
    port = '40506'
    info = "MySQL log files can be set in the MySQL configuration to exist anywhere on the filesystem. It is common practice to ensure that the system filesystem is left uncluttered by application logs. System filesystems include the root, /var, or /usr."
    solution = """Perform the following actions to remediate this setting:
   1. Open the MySQL configuration file (my.cnf)
   2. Locate the log-bin entry and set it to a file not on root ('/'), /var, or /usr"""
    reference = '800-53|SC-5,CSF|PR.DS-4,ITSG-33|SC-5,LEVEL|1S'
    see_also = 'https://benchmarks.cisecurity.org/tools2/mysql/CIS_Oracle_MySQL_Community_Server_5.6_Benchmark_v1.1.0.pdf'
    description_template = "6.2 Ensure Log Files Are Stored on a Non-System Partition [{}]"

    def run(self, config):
        self.set_start_time()
        self.proc = SshTask(config, self.host, "mysql -s -e \"show GLOBAL VARIABLES WHERE Variable_Name = 'log_bin_basename' AND Value LIKE 'C:%' OR Variable_Name = 'log_bin_basename' AND Value = '/' OR Variable_Name = 'log_bin_basename' AND Value = '/var%' OR Variable_Name = 'log_bin_basename' AND Value = '/usr%'\"")
        logging.debug("MySQL 5.6 LogsPartition command was '{}'".format(self.proc.ssh_cmd))
        self.proc.run()

    def poll(self):
        result = self.proc.poll()
        if result is not None:
            self.set_done_time()
        return result

    def finalize(self):
        (self.plugin_output, _) = self.proc.finalize()
        self.plugin_output = self.plugin_output.strip()
        print self.plugin_output
        if re.match(r'^log_error./var', self.plugin_output):
            self.status = DatabaseTest.PASSED
        else:
            self.plugin_output = "Failure from lack of log_error parameter being set by MySQL to OFF."
            self.status = DatabaseTest.FAILED


class LogWarningTest(DatabaseTest):
    benchmark = '6.3'
    risk = DatabaseTest.HIGH
    protocol = 'ssh+mysql'
    port = '40506'
    info = "The error log contains information about events such as mysqld starting and stopping, when a table needs to be checked or repaired, and, depending on the host operating system, stack traces when mysqld fails."
    solution = """Perform the following actions to remediate this setting:
   1. Open the MySQL configuration file (my.cnf or my.ini)
   2. Set the log-error option to the path for the error log"""
    reference = '800-53|AU-12,800-171|3.3.1,800-171|3.3.2,CN-L3|7.1.3.3(a),CN-L3|7.1.3.3(b),CN-L3|7.1.3.3(c),CSF|DE.CM-1,CSF|DE.CM-3,CSF|DE.CM-7,CSF|PR.PT-1,ISO/IEC-27001|A.12.4.1,ITSG-33|AU-12,TBA-FIISB|45.1.1,LEVEL|1S'
    see_also = 'https://benchmarks.cisecurity.org/tools2/mysql/CIS_Oracle_MySQL_Community_Server_5.6_Benchmark_v1.1.0.pdf'
    description_template = "6.3 Ensure 'log_warnings' Is Set to '2' [{}]"

    def run(self, config):
        self.set_start_time()
        self.proc = SshTask(config, self.host, "mysql -s -e \"show variables like 'log_warnings'\" | tail -n 1")
        logging.debug("MySQL 5.6 LogErrorTest command was '{}'".format(self.proc.ssh_cmd))
        self.proc.run()

    def poll(self):
        result = self.proc.poll()
        if result is not None:
            self.set_done_time()
        return result

    def finalize(self):
        (self.plugin_output, _) = self.proc.finalize()
        self.plugin_output = self.plugin_output.strip()
        if re.match(r'2', self.plugin_output):
            self.status = DatabaseTest.PASSED
        else:
            self.plugin_output = "Failure from lack of log_error parameter being set by MySQL to OFF."
            self.status = DatabaseTest.FAILED


class CheckLogRawStatus(DatabaseTest):
    benchmark = '6.5'
    risk = DatabaseTest.HIGH
    protocol = 'ssh+mysql'
    port = '40506'
    description_template = "6.5 Ensure 'log-raw' Is Set to 'OFF' [{}]"
    info = """On Linux/UNIX, the MySQL client logs statements executed interactively to a history
file. By default, this file is named .mysql_history in the user's home directory. Most
interactive commands run in the MySQL client application are saved to a history file. The
MySQL command history should be disabled.
"""
    solution = """
Perform the following steps to remediate this setting:
1. Remove .mysql_history if it exists.
2. Use either of the techniques below to prevent it from being created again:
1. Set the MYSQL_HISTFILE environment variable to /dev/null. This
will need to be placed in the shell's startup script.
2. Create $HOME/.mysql_history as a symbolic to /dev/null.
"""
    reference = '800-53|SC-5,CSF|PR.DS-4,ITSG-33|SC-5,LEVEL|1S'
    see_also = 'https://benchmarks.cisecurity.org/tools2/mysql/CIS_Oracle_MySQL_Community_Server_5.6_Benchmark_v1.1.0.pdf'

    def run(self, config):
        self.set_start_time()
        self.proc = SshTask(config, self.host, "grep -R log-raw /etc/mysql/my.cnf")
        logging.debug("MySQL 5.6 DedicatedMySQLAccount command was '{}'".format(self.proc.ssh_cmd))
        self.proc.run()

    def poll(self):
        result = self.proc.poll()
        if result is not None:
            self.set_done_time()
        return result

    def finalize(self):
        (self.plugin_output, _) = self.proc.finalize()
        self.plugin_output = self.plugin_output.strip()
        if self.plugin_output.splitlines():
            self.status = DatabaseTest.FAILED
        else:
            self.status = DatabaseTest.PASSED


class OldPasswords(DatabaseTest):
    benchmark = '7.2'
    risk = DatabaseTest.HIGH
    protocol = 'ssh+mysql'
    port = '40506'
    info = """This variable controls the password hashing method used by the PASSWORD() function and for the IDENTIFIED BY clause of the CREATE USER and GRANT statements. Before 5.6.6, the value can be 0 (or OFF), or 1 (or ON). As of 5.6.6, the following value can be one of the following:
   - 0 - authenticate with the mysql_native_password plugin
   - 1 - authenticate with the mysql_old_password plugin
   - 2 - authenticate with the sha256_password plugin"""
    solution = """Must not use: --old-passwords"""
    reference = '800-53|IA-5,800-53|SC-13,PCI-DSSv3.1|8.2.1,PCI-DSSv3.2|8.2.1,800-171|3.13.11,800-171|3.5.10,CSF|PR.AC-1,CSF|PR.DS-5,ITSG-33|IA-5,ITSG-33|SC-13,TBA-FIISB|26.1,CSCv6|16.13,CSCv6|16.14,LEVEL|1S'
    see_also = 'https://benchmarks.cisecurity.org/tools2/mysql/CIS_Oracle_MySQL_Community_Server_5.6_Benchmark_v1.1.0.pdf'
    description_template = "7.1 Ensure 'old_passwords' Is Not Set to '1' or 'ON' [{}]"

    def run(self, config):
        self.set_start_time()
        self.proc = SshTask(config, self.host, "mysql -s -e \"SHOW VARIABLES WHERE Variable_name = 'old_passwords'\"")
        logging.debug("MySQL 5.6 OldPasswords command was '{}'".format(self.proc.ssh_cmd))
        self.proc.run()

    def poll(self):
        result = self.proc.poll()
        if result is not None:
            self.set_done_time()
        return result

    def finalize(self):
        (self.plugin_output, _) = self.proc.finalize()
        self.plugin_output = self.plugin_output.strip()
        if re.match(r'^old_passwords.0', self.plugin_output):
            self.status = DatabaseTest.PASSED
        else:
            self.plugin_output = "Failure from lack of old_passwords parameter being set by MySQL to 0."
            self.status = DatabaseTest.FAILED


class SecureAuth(DatabaseTest):
    benchmark = '7.2'
    risk = DatabaseTest.HIGH
    protocol = 'ssh+mysql'
    port = '40506'
    info = "This option dictates whether the server will deny connections by clients that attempt to use accounts that have their password stored in the mysql_old_password format."
    solution = "Add the following line to [mysqld] portions of the MySQL option file to establish the recommended state: secure_auth=ON"
    reference = '800-53|IA-5,800-53|SC-13,PCI-DSSv3.1|8.2.1,PCI-DSSv3.2|8.2.1,800-171|3.13.11,800-171|3.5.10,CSF|PR.AC-1,CSF|PR.DS-5,ITSG-33|IA-5,ITSG-33|SC-13,TBA-FIISB|26.1,CSCv6|16.13,CSCv6|16.14,LEVEL|1S,LEVEL|2S'
    see_also = 'https://benchmarks.cisecurity.org/tools2/mysql/CIS_Oracle_MySQL_Community_Server_5.6_Benchmark_v1.1.0.pdf'
    description_template = "7.2 Ensure 'secure_auth' is set to 'ON' [{}]"

    def run(self, config):
        self.set_start_time()
        self.proc = SshTask(config, self.host, "mysql -s -e \"SHOW VARIABLES WHERE Variable_name = 'secure_auth'\"")
        logging.debug("MySQL 5.6 SecureAuth command was '{}'".format(self.proc.ssh_cmd))
        self.proc.run()

    def poll(self):
        result = self.proc.poll()
        if result is not None:
            self.set_done_time()
        return result

    def finalize(self):
        (self.plugin_output, _) = self.proc.finalize()
        self.plugin_output = self.plugin_output.strip()
        if re.match(r'^secure_auth.ON', self.plugin_output):
            self.status = DatabaseTest.PASSED
        else:
            self.plugin_output = "Failure from lack of secure_auth parameter being set by MySQL to ON."
            self.status = DatabaseTest.FAILED


class CheckMyCnfPasswords(DatabaseTest):
    benchmark = '7.3'
    risk = DatabaseTest.HIGH
    protocol = 'ssh+mysql'
    port = '40506'
    description_template = "7.3 Ensure Passwords Are Not Stored in the Global Configuration [{}]"
    info = """On Linux/UNIX, the MySQL client logs statements executed interactively to a history
file. By default, this file is named .mysql_history in the user's home directory. Most
interactive commands run in the MySQL client application are saved to a history file. The
MySQL command history should be disabled.
"""
    solution = """
Perform the following steps to remediate this setting:
1. Remove .mysql_history if it exists.
2. Use either of the techniques below to prevent it from being created again:
1. Set the MYSQL_HISTFILE environment variable to /dev/null. This
will need to be placed in the shell's startup script.
2. Create $HOME/.mysql_history as a symbolic to /dev/null.
"""
    reference = '800-53|SC-5,CSF|PR.DS-4,ITSG-33|SC-5,LEVEL|1S'
    see_also = 'https://benchmarks.cisecurity.org/tools2/mysql/CIS_Oracle_MySQL_Community_Server_5.6_Benchmark_v1.1.0.pdf'

    def run(self, config):
        self.set_start_time()
        self.proc = SshTask(config, self.host, "grep password /etc/mysql/my.cnf")
        logging.debug("MySQL 5.6 DedicatedMySQLAccount command was '{}'".format(self.proc.ssh_cmd))
        self.proc.run()

    def poll(self):
        result = self.proc.poll()
        if result is not None:
            self.set_done_time()
        return result

    def finalize(self):
        (self.plugin_output, _) = self.proc.finalize()
        self.plugin_output = self.plugin_output.strip()
        if self.plugin_output.splitlines():
            self.status = DatabaseTest.FAILED
        else:
            self.status = DatabaseTest.PASSED


class NoAutoCreateUser(DatabaseTest):
    benchmark = '7.4'
    risk = DatabaseTest.HIGH
    protocol = 'ssh+mysql'
    port = '40506'
    info = "NO_AUTO_CREATE_USER is an option for sql_mode that prevents a GRANT statement from automatically creating a user when authentication information is not provided."
    solution = """Perform the following actions to remediate this setting:
   1. Open the MySQL configuration file (my.cnf)
   2. Find the sql_mode setting in the [mysqld] area
   3. Add the NO_AUTO_CREATE_USER to the sql_mode setting"""
    reference = '800-53|AC-6,PCI-DSSv3.1|7.1.2,PCI-DSSv3.2|7.1.2,800-171|3.1.5,CN-L3|7.1.3.2(b),CN-L3|7.1.3.2(g),CSF|PR.AC-4,CSF|PR.DS-5,ITSG-33|AC-6,LEVEL|1S'
    see_also = 'https://benchmarks.cisecurity.org/tools2/mysql/CIS_Oracle_MySQL_Community_Server_5.6_Benchmark_v1.1.0.pdf'
    description_template = "7.4 Ensure 'sql_mode' Contains 'NO_AUTO_CREATE_USER' - '@@global.sql_mode' [{}]"

    def run(self, config):
        self.set_start_time()
        self.proc = SshTask(config, self.host, "mysql -s -e \"select @@global.sql_mode\"")
        logging.debug("MySQL 5.6 NoAutoCreateUser command was '{}'".format(self.proc.ssh_cmd))
        self.proc.run()

    def poll(self):
        result = self.proc.poll()
        if result is not None:
            self.set_done_time()
        return result

    def finalize(self):
        (self.plugin_output, _) = self.proc.finalize()
        self.plugin_output = self.plugin_output.strip()
        if re.match(r'NO_AUTO_CREATE_USER', self.plugin_output):
            self.status = DatabaseTest.PASSED
        else:
            self.plugin_output = self.plugin_output + "\nExpected NO_AUTO_CREATE_USER."
            self.status = DatabaseTest.FAILED


class BlankPasswords(DatabaseTest):
    benchmark = '7.5'
    risk = DatabaseTest.HIGH
    protocol = 'ssh+mysql'
    port = '40506'
    info = "Blank passwords allow a user to login without using a password."
    solution = """For each row returned from the audit procedure, set a password for the given user using the following statement (as an example):
   SET PASSWORD FOR <user>@'<host>' = PASSWORD('<clear password>')

   NOTE: Replace <user>, <host>, and <clear password> with appropriate values."""
    reference = '800-53|IA-5,CIP|007-6-R5,HIPAA|164.308(a)(5)(ii)(D),PCI-DSSv3.1|8.2.3,PCI-DSSv3.2|8.2.3,800-171|3.5.7,CN-L3|7.1.2.7(e),CN-L3|7.1.3.1(b),CSF|PR.AC-1,ISO/IEC-27001|A.9.4.3,ITSG-33|IA-5,TBA-FIISB|26.2.1,TBA-FIISB|26.2.4,LEVEL|1S,LEVEL|2S'
    see_also = 'https://benchmarks.cisecurity.org/tools2/mysql/CIS_Oracle_MySQL_Community_Server_5.6_Benchmark_v1.1.0.pdf'
    description_template = "7.5 Ensure Passwords Are Set for All MySQL Accounts [{}]"

    def run(self, config):
        self.set_start_time()
        self.proc = SshTask(config, self.host, "mysql -s -e \"SELECT User,host FROM mysql.user WHERE (plugin IN('mysql_native_password', 'mysql_old_password') AND (LENGTH(Password) = 0 OR Password IS NULL)) OR (plugin='sha256_password' AND LENGTH(authentication_string) = 0);\"")
        logging.debug("MySQL 5.6 NoAutoCreateUser command was '{}'".format(self.proc.ssh_cmd))
        self.proc.run()

    def poll(self):
        result = self.proc.poll()
        if result is not None:
            self.set_done_time()
        return result

    def finalize(self):
        (self.plugin_output, _) = self.proc.finalize()
        self.plugin_output = self.plugin_output.strip()
        if self.plugin_output == '':
            self.status = DatabaseTest.PASSED
        else:
            self.status = DatabaseTest.FAILED


class PasswordPolicyPlugin(DatabaseTest):
    benchmark = '7.6'
    risk = DatabaseTest.HIGH
    protocol = 'ssh+mysql'
    port = '40506'
    info = "Password complexity includes password characteristics such as length, case, length, and character sets."
    solution = """Add to the global configuration:
   plugin-load=validate_password.so
   validate-password=FORCE_PLUS_PERMANENT
   validate_password_length=14
   validate_password_mixed_case_count=1
   validate_password_number_count=1
   validate_password_special_char_count=1
   validate_password_policy=MEDIUM

   And change passwords for users which have passwords which are identical to their username."""
    reference = '800-53|IA-5,CIP|007-6-R5,HIPAA|164.308(a)(5)(ii)(D),PCI-DSSv3.1|8.2.3,PCI-DSSv3.2|8.2.3,800-171|3.5.7,CN-L3|7.1.2.7(e),CN-L3|7.1.3.1(b),CSF|PR.AC-1,ISO/IEC-27001|A.9.4.3,ITSG-33|IA-5,TBA-FIISB|26.2.1,TBA-FIISB|26.2.4,LEVEL|1S'
    see_also = 'https://benchmarks.cisecurity.org/tools2/mysql/CIS_Oracle_MySQL_Community_Server_5.6_Benchmark_v1.1.0.pdf'
    description_template = "7.6 Ensure Password Policy Is in Place - 'validate_password_length' [{}]"

    def run(self, config):
        self.set_start_time()
        self.proc = SshTask(config, self.host, "mysql -s -e \"SHOW VARIABLES LIKE 'validate_password_length'\"")
        logging.debug("MySQL 5.6 PasswordPolicyPlugin command was '{}'".format(self.proc.ssh_cmd))
        self.proc.run()

    def poll(self):
        result = self.proc.poll()
        if result is not None:
            self.set_done_time()
        return result

    def finalize(self):
        (self.plugin_output, _) = self.proc.finalize()
        self.plugin_output = self.plugin_output.strip()
        if self.plugin_output != '':
            self.status = DatabaseTest.PASSED
        else:
            self.status = DatabaseTest.FAILED


class NoWildcardHostnames(DatabaseTest):
    benchmark = '7.7'
    risk = DatabaseTest.HIGH
    protocol = 'ssh+mysql'
    port = '40506'
    info = "MySQL can make use of host wildcards when granting permissions to users on specific databases. For example, you may grant a given privilege to '<user>'@'%'."
    solution = """Perform the following actions to remediate this setting:
   1. Enumerate all users returned after running the audit procedure
   2. Either ALTER the user's host to be specific or DROP the user"""
    reference = '800-53|AC-3,800-171|3.1.1,CSF|PR.AC-4,CSF|PR.PT-3,ISO/IEC-27001|A.9.4.1,ITSG-33|AC-3,LEVEL|1S,LEVEL|2S'
    see_also = 'https://benchmarks.cisecurity.org/tools2/mysql/CIS_Oracle_MySQL_Community_Server_5.6_Benchmark_v1.1.0.pdf'
    description_template = "7.7 Ensure No Users Have Wildcard Hostnames [{}]"

    def run(self, config):
        self.set_start_time()
        self.proc = SshTask(config, self.host, "mysql -s -e \"select user,host from mysql.user where host = '%'\"")
        logging.debug("MySQL 5.6 NoWildcardHostnames command was '{}'".format(self.proc.ssh_cmd))
        self.proc.run()

    def poll(self):
        result = self.proc.poll()
        if result is not None:
            self.set_done_time()
        return result

    def finalize(self):
        (self.plugin_output, _) = self.proc.finalize()
        self.plugin_output = self.plugin_output.strip()
        if self.plugin_output == '':
            self.status = DatabaseTest.PASSED
        else:
            self.status = DatabaseTest.FAILED


class NoWildcardUsers(DatabaseTest):
    benchmark = '7.8'
    risk = DatabaseTest.HIGH
    protocol = 'ssh+mysql'
    port = '40506'
    info = "Anonymous accounts are users with empty usernames (''). Anonymous accounts have no passwords, so anyone can use them to connect to the MySQL server."
    solution = """Perform the following actions to remediate this setting:
   1. Enumerate the anonymous users returned from executing the audit procedure
   2. For each anonymous user, DROP or assign them a name

   NOTE: As an alternative, you may execute the mysql_secure_installation utility."""
    reference = '800-53|AC-14,ITSG-33|AC-14,LEVEL|1S'
    see_also = 'https://benchmarks.cisecurity.org/tools2/mysql/CIS_Oracle_MySQL_Community_Server_5.6_Benchmark_v1.1.0.pdf'
    description_template = "7.8 Ensure No Anonymous Accounts Exist [{}]"

    def run(self, config):
        self.set_start_time()
        self.proc = SshTask(config, self.host, "mysql -s -e \"SELECT user,host FROM mysql.user WHERE user = ''\"")
        logging.debug("MySQL 5.6 NoWildcardUsers command was '{}'".format(self.proc.ssh_cmd))
        self.proc.run()

    def poll(self):
        result = self.proc.poll()
        if result is not None:
            self.set_done_time()
        return result

    def finalize(self):
        (self.plugin_output, _) = self.proc.finalize()
        self.plugin_output = self.plugin_output.strip()
        if self.plugin_output == '':
            self.status = DatabaseTest.PASSED
        else:
            self.status = DatabaseTest.FAILED


class HaveSSLTest(DatabaseTest):
    benchmark = '8.1'
    risk = DatabaseTest.HIGH
    protocol = 'ssh+mysql'
    port = '40506'
    info = 'All network traffic must use SSL/TLS when traveling over untrusted networks.'
    solution = """All network traffic must use SSL/TLS when traveling over untrusted networks."""
    reference = '800-53|SC-8,800-171|3.13.8,CSF|PR.DS-2,CSF|PR.DS-5,ISO/IEC-27001|A.13.2.3,ITSG-33|SC-8,TBA-FIISB|29.1,LEVEL|1S'
    see_also = 'https://benchmarks.cisecurity.org/tools2/mysql/CIS_Oracle_MySQL_Community_Server_5.6_Benchmark_v1.1.0.pdf'
    description_template = "8.1 Ensure 'have_ssl' Is Set to 'YES' [{}]"

    def run(self, config):
        self.set_start_time()
        self.proc = SshTask(config, self.host, "mysql -s -e \"SHOW variables WHERE variable_name = 'have_ssl'\"")
        logging.debug("MySQL 5.6 HaveSSLTest command was '{}'".format(self.proc.ssh_cmd))
        self.proc.run()

    def poll(self):
        result = self.proc.poll()
        if result is not None:
            self.set_done_time()
        return result

    def finalize(self):
        (self.plugin_output, _) = self.proc.finalize()
        self.plugin_output = self.plugin_output.strip()
        if re.match('^have_ssl.YES', self.plugin_output):
            self.status = DatabaseTest.PASSED
        else:
            self.status = DatabaseTest.FAILED


class SSLTypeTest(DatabaseTest):
    benchmark = '8.2'
    risk = DatabaseTest.HIGH
    protocol = 'ssh+mysql'
    port = '40506'
    info = "All network traffic must use SSL/TLS when traveling over untrusted networks. SSL/TLS should be enforced on a per-user basis for users which enter the system through the network."
    solution = """Use the GRANT statement to require the use of SSL: GRANT USAGE ON *.* TO 'my_user'@'app1.example.com' REQUIRE SSL; Note that REQUIRE SSL only enforces SSL. There are options like REQUIRE X509, REQUIRE ISSUER, REQUIRE SUBJECT which can be used to further restrict connection options.."""
    reference = '800-53|SC-8,800-171|3.13.8,CSF|PR.DS-2,CSF|PR.DS-5,ISO/IEC-27001|A.13.2.3,ITSG-33|SC-8,TBA-FIISB|29.1,LEVEL|1S'
    see_also = 'https://benchmarks.cisecurity.org/tools2/mysql/CIS_Oracle_MySQL_Community_Server_5.6_Benchmark_v1.1.0.pdf'
    description_template = "8.2 Ensure 'ssl_type' Is Set to 'ANY', 'X509', or 'SPECIFIED' for All Remote Users [{}]"

    def run(self, config):
        self.set_start_time()
        self.proc = SshTask(config, self.host, "mysql -s -e \"SELECT user, host, ssl_type FROM mysql.user WHERE NOT HOST IN ('::1', '127.0.0.1', 'localhost');\"")
        logging.debug("MySQL 5.6 SSLTypeTest command was '{}'".format(self.proc.ssh_cmd))
        self.proc.run()

    def poll(self):
        result = self.proc.poll()
        if result is not None:
            self.set_done_time()
        return result

    def finalize(self):
        (self.plugin_output, _) = self.proc.finalize()
        arr = self.plugin_output.splitlines()
        test = True
        for i in range(0, len(arr)):
            record = arr[i].split('\t')
            if record[0] == '' or record[1] == '' or record[2] == '':
                arr[i] = arr[i] + ' - FAIL'
                test = False

        if test:
            self.status = DatabaseTest.PASSED
        else:
            self.plugin_output = "\n".join(arr)
            self.status = DatabaseTest.FAILED


class SecureFilePriv(DatabaseTest):
    benchmark = '9.2'
    risk = DatabaseTest.HIGH
    protocol = 'ssh+mysql'
    port = '40506'
    info = "The secure_file_priv option restricts to paths used by LOAD DATA INFILE or SELECT local_file. It is recommended that this option be set to a file system location that contains only resources expected to be loaded by MySQL."
    solution = """Add the following line to the [mysqld] section of the MySQL configuration file and restart the MySQL service:
   secure_file_priv=<path_to_load_directory>"""
    reference = '800-53|CM-6,PCI-DSSv3.1|2.2.4,PCI-DSSv3.2|2.2.4,800-171|3.4.2,CSF|PR.IP-1,ITSG-33|CM-6,CSCv6|3.1,LEVEL|1S'
    see_also = 'https://benchmarks.cisecurity.org/tools2/mysql/CIS_Oracle_MySQL_Community_Server_5.6_Benchmark_v1.1.0.pdf'
    description_template = "9.2 Ensure 'master_info_repository' Is Set to 'TABLE' [{}]"

    def run(self, config):
        self.set_start_time()
        self.proc = SshTask(config, self.host, "mysql -sN -e \"SHOW GLOBAL VARIABLES WHERE Variable_name = 'master_info_repository' AND Value<>''\"")
        logging.debug("MySQL 5.6 SecureFilePriv command was '{}'".format(self.proc.ssh_cmd))
        self.proc.run()

    def poll(self):
        result = self.proc.poll()
        if result is not None:
            self.set_done_time()
        return result

    def finalize(self):
        (self.plugin_output, _) = self.proc.finalize()
        self.plugin_output = self.plugin_output.strip()
        if re.match(r'^master_info_repository.*FILE', self.plugin_output):
            self.status = DatabaseTest.FAILED
        else:
            self.status = DatabaseTest.PASSED


class MasterVerifySSLCert(DatabaseTest):
    benchmark = '9.3'
    risk = DatabaseTest.HIGH
    protocol = 'ssh+mysql'
    port = '40506'
    info = "In the MySQL slave context the setting MASTER_SSL_VERIFY_SERVER_CERT indicates whether the slave should verify the master's certificate. This configuration item may be set to Yes or No, and unless SSL has been enabled on the slave, the value will be ignored."
    solution = """To remediate this setting you must use the CHANGE MASTER TO command.
   STOP SLAVE; -- required if replication was already running
   CHANGE MASTER TO MASTER_SSL_VERIFY_SERVER_CERT=1;
   START SLAVE; -- required if you want to restart replication"""
    reference = '800-53|IA-5,CSF|PR.AC-1,ITSG-33|IA-5,LEVEL|1S'
    see_also = 'https://benchmarks.cisecurity.org/tools2/mysql/CIS_Oracle_MySQL_Community_Server_5.6_Benchmark_v1.1.0.pdf'
    description_template = "9.3 Ensure 'MASTER_SSL_VERIFY_SERVER_CERT' Is Set to 'YES' or '1' [{}]"

    def run(self, config):
        self.set_start_time()
        self.proc = SshTask(config, self.host, "mysql -s -e \"select ssl_verify_server_cert from mysql.slave_master_info\"")
        logging.debug("MySQL 5.6 HaveSSLTest command was '{}'".format(self.proc.ssh_cmd))
        self.proc.run()

    def poll(self):
        result = self.proc.poll()
        if result is not None:
            self.set_done_time()
        return result

    def finalize(self):
        (self.plugin_output, _) = self.proc.finalize()
        self.plugin_output = self.plugin_output.strip()
        if re.match(r'1|ON', self.plugin_output):
            self.status = DatabaseTest.PASSED
        else:
            self.status = DatabaseTest.FAILED


class ReplicationSuperPriv(DatabaseTest):
    benchmark = '9.4'
    risk = DatabaseTest.HIGH
    protocol = 'ssh+mysql'
    port = '40506'
    info = "The SUPER privilege found in the mysql.user table governs the use of a variety of MySQL features. These features include, CHANGE MASTER TO, KILL, mysqladmin kill option, PURGE BINARY LOGS, SET GLOBAL, mysqladmin debug option, logging control, and more."
    solution = """Execute the following steps to remediate this setting:
   1. Enumerate the replication users found in the result set of the audit procedure
   2. For each replication user, issue the following SQL statement (replace 'repl' with your replication user's name):

   REVOKE SUPER ON *.* FROM 'repl';"""
    reference = '800-53|AC-6,800-171|3.1.5,CSF|PR.AC-4,ISO/IEC-27001|A.9.2.3,ITSG-33|AC-6,CSCv6|5.1,LEVEL|1S'
    see_also = 'https://benchmarks.cisecurity.org/tools2/mysql/CIS_Oracle_MySQL_Community_Server_5.6_Benchmark_v1.1.0.pdf'
    description_template = "9.4 Ensure 'super_priv' Is Not Set to 'Y' for Replication Users [{}]"

    def run(self, config):
        self.set_start_time()
        self.proc = SshTask(config, self.host, "mysql -s -e \"select user, host from mysql.user where user='repl' and Super_priv = 'Y'\"")
        logging.debug("MySQL 5.6 ReplicationSuperPriv command was '{}'".format(self.proc.ssh_cmd))
        self.proc.run()

    def poll(self):
        result = self.proc.poll()
        if result is not None:
            self.set_done_time()
        return result

    def finalize(self):
        (self.plugin_output, _) = self.proc.finalize()
        self.plugin_output = self.plugin_output.strip()
        if self.plugin_output == '':
            self.status = DatabaseTest.PASSED
        else:
            self.status = DatabaseTest.FAILED


class NoWildcardReplication(DatabaseTest):
    benchmark = '9.5'
    risk = DatabaseTest.HIGH
    protocol = 'ssh+mysql'
    port = '40506'
    info = "The SUPER privilege found in the mysql.user table governs the use of a variety of MySQL features. These features include, CHANGE MASTER TO, KILL, mysqladmin kill option, PURGE BINARY LOGS, SET GLOBAL, mysqladmin debug option, logging control, and more."
    solution = """Execute the following steps to remediate this setting:
   1. Enumerate the replication users found in the result set of the audit procedure
   2. For each replication user, issue the following SQL statement (replace 'repl' with your replication user's name):

   REVOKE SUPER ON *.* FROM 'repl';"""
    reference = '800-53|AC-6,800-171|3.1.5,CSF|PR.AC-4,ISO/IEC-27001|A.9.2.3,ITSG-33|AC-6,CSCv6|5.1,LEVEL|1S'
    see_also = 'https://benchmarks.cisecurity.org/tools2/mysql/CIS_Oracle_MySQL_Community_Server_5.6_Benchmark_v1.1.0.pdf'
    description_template = "9.4 Ensure 'super_priv' Is Not Set to 'Y' for Replication Users [{}]"

    def run(self, config):
        self.set_start_time()
        self.proc = SshTask(config, self.host, "mysql -s -e \"SELECT user, host FROM mysql.user WHERE user='repl' AND host = '%'\"")
        logging.debug("MySQL 5.6 NoWildcardReplication command was '{}'".format(self.proc.ssh_cmd))
        self.proc.run()

    def poll(self):
        result = self.proc.poll()
        if result is not None:
            self.set_done_time()
        return result

    def finalize(self):
        (self.plugin_output, _) = self.proc.finalize()
        self.plugin_output = self.plugin_output.strip()
        if self.plugin_output == '':
            self.status = DatabaseTest.PASSED
        else:
            self.status = DatabaseTest.FAILED
