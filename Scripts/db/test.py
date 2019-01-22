import logging
from datetime import datetime, timedelta

class DatabaseTest:
    """General type for database tests. This is supposed to work similarly
    to the unittest test module.
    """
    cve = None
    cvss = None
    risk = None
    protocol = None
    port = None
    name = "Unix Compliance Checks"
    synopsis = "Compliance checks for Unix systems"
    solution = None
    see_also = None
    plugin_output = None
    info = None

    description_template = "[{}]"

    timeout = timedelta(minutes=3)

    # risk levels
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"
    
    # some potential states
    NEEDS_RUN      = "NEEDS_RUN"
    PASSED         = "PASSED"
    WARNING        = "WARNING"
    FAILED         = "FAILED"
    ABORTED        = "ABORTED"
    NEEDS_FINALIZE = "NEEDS_FINALIZE"
    NO_MATCH       = "NO_MATCH"


    def __init__(self, host, on_success=None):
        """This follows the CSV output of a Nessus scan to pantomime being the
        same thing and make it easy to pull in the common language and
        references of audit files.

        'plugin_id' is test ID and is invented by the frameworka round
        the test, not the test itself.

        'host' should be the FQDN or IP.

        'on_success' should be a list of other tests to run after.
        """
        self.host = host
        self.plugin_id = -1
        self.status = self.NEEDS_RUN
        self.on_success = on_success

        self.init_ts = datetime.utcnow() # when was it enqueued
        self.start_ts = None # when was the last time we touched it
        self.done_ts = None # when were we done

        logging.debug('New DatabaseTest: {} host: {}'.format(self.__class__.__name__, self.host))

    def run(self, config):
        """Override this to add your test. Set the status on the way out.

        `config` is the top-level config map.
        """
        return True

    def poll(self):
        """Equivalent to `subprocess.Popen.poll()` in in practical usage, but
        returns True/False depending on the poll output, and also updates the last 
        """
        return True

    def set_start_time(self):
        logging.debug('Starting DatabaseTest: {} host: {}'.format(self.__class__.__name__, self.host))
        self.start_ts = datetime.utcnow()

    def set_done_time(self):
        logging.debug('Ending DatabaseTest: {} host: {}'.format(self.__class__.__name__, self.host))
        self.done_ts = datetime.utcnow()

    def __repr__(self):
        return str(self.to_dict())

    def to_dict(self):
        return {'test_name': self.__class__.__name__,
                'host': self.host,
                'status': self.status,
                'time': {'init': self.init_ts,
                         'start': self.start_ts,
                         'done': self.done_ts,
                         'timeout': self.timeout},
                'report_data': { 'cve': self.cve,
                                 'cvss': self.cvss,
                                 'risk': self.risk,
                                 'host': self.host,
                                 'protocol': self.protocol,
                                 'port': self.port,
                                 'name': self.name,
                                 'synopsis': self.synopsis,
                                 'description': self.description_template.format(self.status),
                                 'solution': self.solution,
                                 'see_also': self.see_also,
                                 'plugin_output': self.plugin_output }}
