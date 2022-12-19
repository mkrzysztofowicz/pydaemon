"""
PyDaemon: a daemon implementation in Python 3

This file implements the Daemon class, which can be subclassed by your daemon script
"""

import atexit
import configparser
from ctypes import c_int16, sizeof
import grp
import logging
import logging.handlers
import os
import pwd
import signal
import sys
import time


__all__ = ["Daemon"]


class Daemon(object):
    """
    A generic daemon class

    Subclass the Daemon class and override the run() method
    """

    def __init__(self, pidfile, config_file=None,
                 stdin='/dev/null', stdout='/dev/null', stderr='/dev/null', daemon_name="Daemon"):
        self.stdin = stdin
        self.stdout = stdout
        self.stderr = stderr
        self.pidfile = pidfile
        self.username = None
        self.name = daemon_name
        self.logger = logging.getLogger(self.name)
        self.setup_logging()
        self.config_file = config_file
        self.configuration = None
        self.dont_daemonize = False

    def configure(self):
        """
        Parse the configuration file and configure the daemon.
        This method has to be overridden when subclassing the Daemon.
        """
        raise NotImplementedError

    def setup_logging(self):
        """
        Set up the logging system.

        This will set the format for all log messages, configure the logging system to send messages to syslog via
        a special file /dev/log. In addition, the logging system will be configured to log all uncaught exceptions
        to assist in troubleshooting.
        """
        logformatter = logging.Formatter('%(name)s[%(process)s]: [%(levelname)s] %(funcName)s: %(message)s')

        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.ERROR)
        console_handler.setFormatter(logformatter)
        self.logger.addHandler(console_handler)

        if os.path.exists('/dev/log'):
            syslog_handler = logging.handlers.SysLogHandler('/dev/log',
                                                            facility=logging.handlers.SysLogHandler.LOG_DAEMON)
            syslog_handler.setFormatter(logformatter)
            self.logger.addHandler(syslog_handler)

        # catch all unhandled exceptions
        sys.excepthook = self.exception_log_handler

    def exception_log_handler(self, atype, value, tb):
        """
        The uncaught exceptions log handler method. This will log any uncaught exception.
        """
        self.logger.exception('Uncaught exception: {}: {}: {}'.format(str(atype), str(value), str(tb)))

    def attach_stream(self, name, mode):
        """
        Replaces the stream with a new one
        :param str name: name of the class property which stores the file name for the stream
                         (e.g. for self.stdin this should be 'stdin')
        :param str mode: file access mode ('r', 'w', 'a', etc, as per the open() call)
        """
        stream = open(getattr(self, name), mode)
        os.dup2(stream.fileno(), getattr(sys, name).fileno())

    def detach_process(self):
        """
        Detach the process from the environment.
        """

        self.fork()     # first fork, detach from parent

        # Become a process group and session group leader
        os.setsid()

        # change to root directory
        os.chdir('/')

        # Ensure complete control over the files the daemon creates
        os.umask(0)

        self.fork()     # second fork, relinquish session leadership

    def fork(self):
        """
        Spawn the child process
        """
        try:
            pid = os.fork()
            if pid > 0:
                raise SystemExit(0)  # parent exits
        except OSError as e:
            self.logger.error("Fork failed: {} ({})".format(e.errno, e.strerror))
            raise SystemExit(1)

    def create_pidfile(self):
        """
        Create a pid file and save the pid.
        """
        atexit.register(self.delete_pidfile)
        pid = str(os.getpid())
        try:
            open(self.pidfile, 'w+').write("{}\n".format(pid))
        except OSError as e:
            self.logger.error("Error creating PID file {}: {} ({})".format(self.pidfile, e.errno, e.strerror))
            raise SystemExit(1)

    def delete_pidfile(self):
        """
        Remove the pid file
        """
        os.remove(self.pidfile)

    @staticmethod
    def pid_exists(pid):
        """
        Check if a process with a given process ID is already running.

        This method uses a fact that kill signal 0 doesn't actually do anything to a running process. If a process
        with a given PID does exist and the user doesn't have the permissions to send it a signal, the permissions
        denied exception will be raised (meaning the process with a given ID *does* exist), or nothing will happen
        at all. If the process doesn't exist, ProcessLookupError exception will be raised instead.

        :param int pid: process ID to check
        :return: False if no process with a given PID is running, True otherwise
        """
        if pid < 0:
            return False
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return False
        else:
            return True

    def get_pid(self):
        """
        Return the Process ID of the running process.
        :return: pid of the currently running process
        :rtype: int
        """
        try:
            pf = open(self.pidfile, 'r')
            pid = int(pf.read().strip())
            pf.close()
        except (IOError, TypeError):
            pid = None
        return pid

    def status(self):
        """
        This method runs when the 'status' action was specified as run time argument to the daemon.
        It will return a dict with two fields: a message to say if the daemon is running and a pid (or None).
        :return: a dict with a message and a pid. If not running, pid will be None.
        """
        pid = self.get_pid()
        if pid and self.pid_exists(pid):
            message = "{} is running, pid: {}".format(self.name, pid)
        else:
            message = "{} not running".format(self.name)

        return {
            "message": message,
            "pid": pid
        }

    def daemonize(self):
        """
        Make a daemon out of the process by detaching from the environment and forking. If username is specified,
        this method will also cause the daemon to drop privileges to those of the specified user.
        Also register sigterm handler.
        """

        def __fdmax():
            bit_size = sizeof(c_int16) * 8
            limit = 2 ** (bit_size - 1)
            return 2 * limit - 1

        if self.dont_daemonize:
            return

        self.detach_process()

        self.create_pidfile()

        # Flush I/O buffers
        sys.stdout.flush()
        sys.stderr.flush()

        # close all open file descriptors
        os.closerange(0, __fdmax())

        # ensure stdin, stdout, stderr are redirected to /dev/null
        # so that the daemon does not output anything to the console
        self.attach_stream('stdin', mode='r')
        self.attach_stream('stdout', mode='w')
        self.attach_stream('stderr', mode='w')

        # Setup signal handlers
        # signal.signal(signal.SIGHUP, self.sighup_handler)
        signal.signal(signal.SIGINT, self.sigterm_handler)
        signal.signal(signal.SIGQUIT, self.sigterm_handler)
        signal.signal(signal.SIGTERM, self.sigterm_handler)

        signal.signal(signal.SIGUSR1, self.sigusr_handler)
        signal.signal(signal.SIGUSR2, self.sigusr_handler)

        if self.username:
            self.drop_privileges()

    def start(self):
        """
        Start the daemon
        """

        self.logger.info("Starting.")

        # check for a pid to see if the daemon is already running
        pid = self.get_pid()

        if pid:
            if self.pid_exists(pid):
                message = "pidfile {} already exists. {} already running?".format(self.pidfile, self.name)
                self.logger.error(message)
                raise SystemExit(1)
            else:
                message = "removing stale pid file"
                self.logger.info(message)
                self.delete_pidfile()

        # Start the daemon
        self.daemonize()
        self.run()

    def stop(self, silent=False):
        """
        Stop the daemon
        """

        # get the pid from the pidfile
        pid = self.get_pid()

        if not pid:
            if not silent:
                message = "pidfile {} does not exist. {} not running?".format(self.pidfile, self.name)
                self.logger.info(message)
            return  # not an error in a restart

        # Try killing the daemon first
        try:
            while True:
                os.kill(pid, signal.SIGTERM)
                time.sleep(0.1)
        except OSError as e:
            e = str(e)
            if e.find("No such process") > 0:
                if os.path.exists(self.pidfile):
                    os.remove(self.pidfile)
            else:
                self.logger.error(e)
                raise SystemExit(1)

    def restart(self):
        """
        Restart the daemon
        """
        self.stop(silent=True)

        if self.config_file is not None:
            self.logger.info("Reloading configuration")
            self.configuration = configparser.ConfigParser(interpolation=configparser.ExtendedInterpolation())
            self.configure()

        self.start()

    def drop_privileges(self):
        """
        Drop privileges if running as root
        """

        if os.getuid() != 0:
            self.logger.info('drop_privileges: not running as root, nothing to do')
            # we're not running as root, so nothing to do
            return

        try:
            pwnam = pwd.getpwnam(self.username)
            uid = pwnam.pw_uid

        except Exception as e:
            self.logger.error(str(e))
            raise SystemExit(1)

        # reset group privileges
        try:
            groups = [g.gr_gid for g in grp.getgrall() if self.username in g.gr_mem]
            os.setgroups(groups)
        except Exception as e:
            self.logger.error(str(e))
            raise SystemExit(1)

        # try setting new uid
        try:
            os.setuid(uid)

        except Exception as e:
            self.logger.error(str(e))
            raise SystemExit(1)

        # ensure reasonable mask
        os.umask(0o22)

    def sigterm_handler(self, signo, frame):
        """
        Sigterm handler method. By default, this will simply log a message to say the daemon is terminating and
        then exit.

        If any extra functionality needed, this method should be overridden in the child class.
        """

        self.logger.warning("Exiting.")
        raise SystemExit(1)

    def sigusr_handler(self, signo, frame):
        """
        Siginfo handler method. By default, this will simply display the status.
        """

        self.logger.info("Received SIGUSR signal: {}".format(signo))
        status = self.status()
        self.logger.info(status["message"])
        print(status["message"])

    def run(self):
        """
        Override this method when subclassing Daemon
        """
        raise NotImplementedError
