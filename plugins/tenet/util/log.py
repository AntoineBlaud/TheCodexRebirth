import os
import sys
import logging
from pathlib import Path
from .misc import makedirs, is_plugin_dev
from .common import get_temp_dir
from ..integration.api import disassembler

# ------------------------------------------------------------------------------
# Log / Print helpers
# ------------------------------------------------------------------------------


def pmsg(message):
    """
    Print a 'plugin message' to the disassembler output window.
    """

    # prefix the message
    prefix_message = "[Tenet] %s" % message

    # only print to disassembler if its output window is alive
    if disassembler.is_msg_inited():
        disassembler.message(prefix_message)
    else:
        logger.info(message)


def get_log_dir():
    """
    Return the plugin log directory.
    """
    root_dir = disassembler.get_root_filename_dir()
    if not root_dir:
        root_dir = Path.home()
    log_directory = os.path.join(root_dir, "tenet_logs")
    # create directory if it does not exist
    if not os.path.exists(log_directory):
        os.makedirs(log_directory)
    return log_directory


def logging_started():
    """
    Check if logging has been started.
    """
    return "logger" in globals()


# ------------------------------------------------------------------------------
# Logger Proxy
# ------------------------------------------------------------------------------


class LoggerProxy(object):
    """
    Fake file-like stream object that redirects writes to a logger instance.
    """

    def __init__(self, logger, stream, log_level=logging.INFO):
        self._logger = logger
        self._log_level = log_level
        self._stream = stream

    def write(self, buf):
        for line in buf.rstrip().splitlines():
            self._logger.log(self._log_level, line.rstrip())
        if self._stream:
            self._stream.write(buf)

    def flush(self):
        pass

    def isatty(self):
        pass


def get_log_path():
    """
    Return the log path for the current plugin session.
    """
    return os.path.join(get_log_dir(), "tenet.%s-%s.log" % (disassembler.get_root_filename(), os.getpid()))


# ------------------------------------------------------------------------------
# Initialize Logging
# ------------------------------------------------------------------------------

MAX_LOGS = 10


def cleanup_log_directory(log_directory):
    """
    Retain only the last 15 logs.
    """
    filetimes = {}

    # build a map of all the files in the directory, and their last modified time
    for log_name in os.listdir(log_directory):
        filepath = os.path.join(log_directory, log_name)
        if os.path.isfile(filepath):
            filetimes[os.path.getmtime(filepath)] = filepath

    # get the filetimes and check if there's enough to warrant cleanup
    times = list(filetimes.keys())
    if len(times) < MAX_LOGS:
        return

    logger.debug("Cleaning logs directory")

    # discard the newest 15 logs
    times.sort(reverse=True)
    times = times[MAX_LOGS:]

    # loop through the remaining older logs, and delete them
    for log_time in times:
        try:
            os.remove(filetimes[log_time])
        except Exception as e:
            logger.error("Failed to delete log %s" % filetimes[log_time])
            logger.error(e)


def start_logging():
    global logger

    # create the plugin logger
    logger = logging.getLogger("Tenet")

    #
    # only enable logging if the plugin-specific environment variable is
    # present. otherwive we return a stub logger to sinkhole messages.
    #

    # if not is_plugin_dev():
    #     logger.disabled = True
    #     return logger

    # create a directory for plugin logs if it does not exist
    log_dir = get_log_dir()
    try:
        makedirs(log_dir)
    except Exception as e:
        print("Failed to create log directory: %s" % log_dir)
        logger.disabled = True
        return logger
    # construct the full log path
    log_path = get_log_path()

    # config the logger
    logging.basicConfig(
        format="%(asctime)s | %(name)28s | %(levelname)7s: %(message)s",
        datefmt="%m-%d-%Y %H:%M:%S",
        level=logging.DEBUG,
        filename=log_path,
    )

    # proxy STDOUT/STDERR to the log files too
    stdout_logger = logging.getLogger("Tenet.STDOUT")
    stderr_logger = logging.getLogger("Tenet.STDERR")
    # sys.stdout = LoggerProxy(stdout_logger, sys.stdout, logging.INFO)
    # sys.stderr = LoggerProxy(stderr_logger, sys.stderr, logging.ERROR)

    logger = logging.getLogger("Tenet")
    logger.info("Log file: %s" % log_path)

    # limit the number of logs we keep
    cleanup_log_directory(log_dir)

    return logger


# ------------------------------------------------------------------------------
# Log Helpers
# ------------------------------------------------------------------------------


def log_config_warning(self, logger, section, field):
    logger.warning("Config missing field '%s' in section '%s", field, section)
