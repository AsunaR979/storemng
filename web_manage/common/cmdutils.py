"""
System-level utilities and helper functions.
"""

import functools
import logging
import multiprocessing
import os
import random
import shlex
import signal
import sys
import time

import enum
import six
import subprocess
from web_manage.common import encodeutils
from threading import Timer

logger = logging.getLogger(__name__)

class InvalidArgumentError(Exception):
    def __init__(self, message=None):
        super(InvalidArgumentError, self).__init__(message)


class UnknownArgumentError(Exception):
    def __init__(self, message=None):
        super(UnknownArgumentError, self).__init__(message)


class ProcessExecutionError(Exception):
    def __init__(self, stdout=None, stderr=None, exit_code=None, cmd=None,
                 description=None):
        super(ProcessExecutionError, self).__init__(
            stdout, stderr, exit_code, cmd, description)
        self.exit_code = exit_code
        self.stderr = stderr
        self.stdout = stdout
        self.cmd = cmd
        self.description = description

    def __str__(self):
        description = self.description
        if description is None:
            description = ("Unexpected error while running command.")

        exit_code = self.exit_code
        if exit_code is None:
            exit_code = '-'

        message = ('%(description)s\n'
                    'Command: %(cmd)s\n'
                    'Exit code: %(exit_code)s\n'
                    'Stdout: %(stdout)r\n'
                    'Stderr: %(stderr)r') % {'description': description,
                                             'cmd': self.cmd,
                                             'exit_code': exit_code,
                                             'stdout': self.stdout,
                                             'stderr': self.stderr}
        return message


class NoRootWrapSpecified(Exception):
    def __init__(self, message=None):
        super(NoRootWrapSpecified, self).__init__(message)


def _subprocess_setup(on_preexec_fn):
    # Python installs a SIGPIPE handler by default. This is usually not what
    # non-Python subprocesses expect.
    signal.signal(signal.SIGPIPE, signal.SIG_DFL)
    if on_preexec_fn:
        on_preexec_fn()


@enum.unique
class LogErrors(enum.IntEnum):
    """Enumerations that affect if stdout and stderr are logged on error.

    .. versionadded:: 2.7
    """

    #: No logging on errors.
    DEFAULT = 0

    #: Log an error on **each** occurence of an error.
    ALL = 1

    #: Log an error on the last attempt that errored **only**.
    FINAL = 2


# Retain these aliases for a number of releases...
LOG_ALL_ERRORS = LogErrors.ALL
LOG_FINAL_ERROR = LogErrors.FINAL
LOG_DEFAULT_ERROR = LogErrors.DEFAULT


def timeout_callback(p):
    try:
        if p.poll() is None:
            logger.info("running cmd timeout, kill")
            os.killpg(p.pid, signal.SIGKILL)
    except Exception as e:
        logger.error("timeout, killpg failed:%s", e)


def execute(*cmd, **kwargs):
    """Helper method to shell out and execute a command through subprocess.

    Allows optional retry.

    :param cmd:             Passed to subprocess.Popen.
    :type cmd:              string
    :param cwd:             Set the current working directory
    :type cwd:              string
    :param process_input:   Send to opened process.
    :type process_input:    string or bytes
    :param env_variables:   Environment variables and their values that
                            will be set for the process.
    :type env_variables:    dict
    :param check_exit_code: Single bool, int, or list of allowed exit
                            codes.  Defaults to [0].  Raise
                            :class:`ProcessExecutionError` unless
                            program exits with one of these code.
    :type check_exit_code:  boolean, int, or [int]
    :param delay_on_retry:  True | False. Defaults to True. If set to True,
                            wait a short amount of time before retrying.
    :type delay_on_retry:   boolean
    :param attempts:        How many times to retry cmd.
    :type attempts:         int
    :param run_as_root:     True | False. Defaults to False. If set to True,
                            the command is prefixed by the command specified
                            in the root_helper kwarg.
    :type run_as_root:      boolean
    :param root_helper:     command to prefix to commands called with
                            run_as_root=True
    :type root_helper:      string
    :param shell:           whether or not there should be a shell used to
                            execute this command. Defaults to false.
    :type shell:            boolean
    :param loglevel:        log level for execute commands.
    :type loglevel:         int.  (Should be logging.DEBUG or logging.INFO)
    :param log_errors:      Should stdout and stderr be logged on error?
                            Possible values are
                            :py:attr:`~.LogErrors.DEFAULT`,
                            :py:attr:`~.LogErrors.FINAL`, or
                            :py:attr:`~.LogErrors.ALL`. Note that the
                            values :py:attr:`~.LogErrors.FINAL` and
                            :py:attr:`~.LogErrors.ALL`
                            are **only** relevant when multiple attempts of
                            command execution are requested using the
                            ``attempts`` parameter.
    :type log_errors:       :py:class:`~.LogErrors`
    :param binary:          On Python 3, return stdout and stderr as bytes if
                            binary is True, as Unicode otherwise.
    :type binary:           boolean
    :param on_execute:      This function will be called upon process creation
                            with the object as a argument.  The Purpose of this
                            is to allow the caller of `processutils.execute` to
                            track process creation asynchronously.
    :type on_execute:       function(:class:`subprocess.Popen`)
    :param on_completion:   This function will be called upon process
                            completion with the object as a argument.  The
                            Purpose of this is to allow the caller of
                            `processutils.execute` to track process completion
                            asynchronously.
    :type on_completion:    function(:class:`subprocess.Popen`)
    :param preexec_fn:      This function will be called
                            in the child process just before the child
                            is executed. WARNING: On windows, we silently
                            drop this preexec_fn as it is not supported by
                            subprocess.Popen on windows (throws a
                            ValueError)
    :type preexec_fn:       function()
    :param prlimit:         Set resource limits on the child process. See
                            below for a detailed description.
    :type prlimit:          :class:`ProcessLimits`
    :param python_exec:     The python executable to use for enforcing
                            prlimits. If this is not set it will default to use
                            sys.executable.
    :type python_exec:      string
    :returns:               (stdout, stderr) from process execution
    :raises:                :class:`UnknownArgumentError` on
                            receiving unknown arguments
    :raises:                :class:`ProcessExecutionError`
    :raises:                :class:`OSError`
    """

    cwd = kwargs.pop('cwd', None)
    process_input = kwargs.pop('process_input', None)
    if process_input is not None:
        process_input = encodeutils.to_utf8(process_input)
    env_variables = kwargs.pop('env_variables', None)
    check_exit_code = kwargs.pop('check_exit_code', [0])
    ignore_exit_code = kwargs.pop('ignore_exit_code', False)
    delay_on_retry = kwargs.pop('delay_on_retry', True)
    attempts = kwargs.pop('attempts', 1)
    run_as_root = kwargs.pop('run_as_root', False)
    root_helper = kwargs.pop('root_helper', '')
    shell = kwargs.pop('shell', False)
    loglevel = kwargs.pop('loglevel', logging.DEBUG)
    log_errors = kwargs.pop('log_errors', None)
    if log_errors is None:
        log_errors = LogErrors.DEFAULT
    binary = kwargs.pop('binary', False)
    on_execute = kwargs.pop('on_execute', None)
    on_completion = kwargs.pop('on_completion', None)
    preexec_fn = kwargs.pop('preexec_fn', os.setsid)
    prlimit = kwargs.pop('prlimit', None)
    python_exec = kwargs.pop('python_exec', sys.executable)
    timeout = kwargs.pop('timeout', None)

    if isinstance(check_exit_code, bool):
        ignore_exit_code = not check_exit_code
        check_exit_code = [0]
    elif isinstance(check_exit_code, int):
        check_exit_code = [check_exit_code]

    if kwargs:
        raise UnknownArgumentError('Got unknown keyword args: %r' % kwargs)

    if isinstance(log_errors, six.integer_types):
        log_errors = LogErrors(log_errors)
    if not isinstance(log_errors, LogErrors):
        raise InvalidArgumentError('Got invalid arg log_errors: %r' %
                                   log_errors)

    if run_as_root and hasattr(os, 'geteuid') and os.geteuid() != 0:
        if not root_helper:
            raise NoRootWrapSpecified(
                message='Command requested root, but did not '
                          'specify a root helper.')
        if shell:
            # root helper has to be injected into the command string
            cmd = [' '.join((root_helper, cmd[0]))] + list(cmd[1:])
        else:
            # root helper has to be tokenized into argument list
            cmd = shlex.split(root_helper) + list(cmd)

    cmd = [str(c) for c in cmd]

    if prlimit:
        if os.name == 'nt':
            logger.info(loglevel,
                    ('Process resource limits are ignored as '
                      'this feature is not supported on Windows.'))
        else:
            args = [python_exec, '-m', 'oslo_concurrency.prlimit']
            args.extend(prlimit.prlimit_args())
            args.append('--')
            args.extend(cmd)
            cmd = args

    while attempts > 0:
        attempts -= 1

        try:
            logger.info(loglevel, ('Running cmd (subprocess): %s'), cmd)
            _PIPE = subprocess.PIPE  # pylint: disable=E1101

            if os.name == 'nt':
                on_preexec_fn = None
                close_fds = False
            else:
                on_preexec_fn = functools.partial(_subprocess_setup,
                                                  preexec_fn)
                close_fds = True

            obj = subprocess.Popen(cmd,
                                   stdin=_PIPE,
                                   stdout=_PIPE,
                                   stderr=_PIPE,
                                   close_fds=close_fds,
                                   preexec_fn=on_preexec_fn,
                                   shell=shell,  # nosec:B604
                                   cwd=cwd,
                                   env=env_variables)
            if timeout:
                my_timer = Timer(timeout, timeout_callback, [obj])
                my_timer.start()
            if on_execute:
                on_execute(obj)

            try:
                result = obj.communicate(process_input)
                obj.stdin.close()  # pylint: disable=E1101
                _returncode = obj.returncode  # pylint: disable=E1101
                logger.info(loglevel, 'CMD "%s" returned: %s', cmd, _returncode)
            finally:
                if on_completion:
                    on_completion(obj)

            if not ignore_exit_code and _returncode not in check_exit_code:
                (stdout, stderr) = result
                if six.PY3:
                    stdout = os.fsdecode(stdout)
                    stderr = os.fsdecode(stderr)
                raise ProcessExecutionError(exit_code=_returncode,
                                            stdout=stdout,
                                            stderr=stderr,
                                            cmd=cmd)
            if six.PY3 and not binary and result is not None:
                (stdout, stderr) = result
                # Decode from the locale using using the surrogateescape error
                # handler (decoding cannot fail)
                stdout = os.fsdecode(stdout)
                stderr = os.fsdecode(stderr)
                return (stdout, stderr)
            else:
                return result

        except (ProcessExecutionError, OSError) as err:
            # if we want to always log the errors or if this is
            # the final attempt that failed and we want to log that.
            if log_errors == LOG_ALL_ERRORS or (
                    log_errors == LOG_FINAL_ERROR and not attempts):
                if isinstance(err, ProcessExecutionError):
                    format = ('%(desc)r\ncommand: %(cmd)r\n'
                               'exit code: %(code)r\nstdout: %(stdout)r\n'
                               'stderr: %(stderr)r')
                    logger.info(loglevel, format, {"desc": err.description,
                                               "cmd": err.cmd,
                                               "code": err.exit_code,
                                               "stdout": err.stdout,
                                               "stderr": err.stderr})
                else:
                    format = ('Got an OSError\ncommand: %(cmd)r\n'
                               'errno: %(errno)r')
                    logger.info(loglevel, format, {"cmd": cmd,
                                               "errno": err.errno})

            if not attempts:
                logger.info(loglevel, ('%r failed. Not Retrying.'),
                        cmd)
                raise
            else:
                logger.info(loglevel, ('%r failed. Retrying.'),
                        cmd)
                if delay_on_retry:
                    time.sleep(random.randint(20, 200) / 100.0)
        finally:
            # NOTE(termie): this appears to be necessary to let the subprocess
            #               call clean something up in between calls, without
            #               it two execute calls in a row hangs the second one
            # NOTE(bnemec): termie's comment above is probably specific to the
            #               eventlet subprocess module, but since we still
            #               have to support that we're leaving the sleep.  It
            #               won't hurt anything in the stdlib case anyway.
            time.sleep(0)


def trycmd(*args, **kwargs):
    """A wrapper around execute() to more easily handle warnings and errors.

    Returns an (out, err) tuple of strings containing the output of
    the command's stdout and stderr.  If 'err' is not empty then the
    command can be considered to have failed.

    :param discard_warnings:  True | False. Defaults to False. If set to True,
                              then for succeeding commands, stderr is cleared
    :type discard_warnings:   boolean
    :returns:                 (out, err) from process execution

    """
    discard_warnings = kwargs.pop('discard_warnings', False)

    try:
        out, err = execute(*args, **kwargs)
        failed = False
    except ProcessExecutionError as exn:
        out, err = '', six.text_type(exn)
        failed = True

    if not failed and discard_warnings and err:
        # Handle commands that output to stderr but otherwise succeed
        err = ''

    return out, err


def ssh_execute(ssh, cmd, process_input=None,
                addl_env=None, check_exit_code=True,
                binary=False, timeout=None,
                sanitize_stdout=True):
    """Run a command through SSH.

    :param ssh:             An SSH Connection object.
    :param cmd:             The command string to run.
    :param check_exit_code: If an exception should be raised for non-zero
                            exit.
    :param timeout:         Max time in secs to wait for command execution.
    :param sanitize_stdout: Defaults to True. If set to True, stdout is
                            sanitized i.e. any sensitive information like
                            password in command output will be masked.
    :returns:               (stdout, stderr) from command execution through
                            SSH.

    .. versionchanged:: 1.9
       Added *binary* optional parameter.
    """
    # sanitized_cmd = strutils.mask_password(cmd)
    sanitized_cmd = cmd
    logger.debug('Running cmd (SSH): %s', sanitized_cmd)
    if addl_env:
        raise InvalidArgumentError('Environment not supported over SSH')

    if process_input:
        # This is (probably) fixable if we need it...
        raise InvalidArgumentError('process_input not supported over SSH')

    stdin_stream, stdout_stream, stderr_stream = ssh.exec_command(
        cmd, timeout=timeout)
    channel = stdout_stream.channel

    # NOTE(justinsb): This seems suspicious...
    # ...other SSH clients have buffering issues with this approach
    stdout = stdout_stream.read()
    stderr = stderr_stream.read()

    stdin_stream.close()

    exit_status = channel.recv_exit_status()

    if six.PY3:
        # Decode from the locale using using the surrogateescape error handler
        # (decoding cannot fail). Decode even if binary is True because
        # mask_password() requires Unicode on Python 3
        stdout = os.fsdecode(stdout)
        stderr = os.fsdecode(stderr)

    # if sanitize_stdout:
    #     stdout = strutils.mask_password(stdout)
    #
    # stderr = strutils.mask_password(stderr)

    # exit_status == -1 if no exit code was returned
    if exit_status != -1:
        logger.debug('Result was %s' % exit_status)
        if check_exit_code and exit_status != 0:
            # In case of errors in command run, due to poor implementation of
            # command executable program, there might be chance that it leaks
            # sensitive information like password to stdout. In such cases
            # stdout needs to be sanitized even though sanitize_stdout=False.
            # stdout = strutils.mask_password(stdout)
            raise ProcessExecutionError(exit_code=exit_status,
                                        stdout=stdout,
                                        stderr=stderr,
                                        cmd=sanitized_cmd)

    if binary:
        if six.PY2:
            # On Python 2, stdout is a bytes string if mask_password() failed
            # to decode it, or an Unicode string otherwise. Encode to the
            # default encoding (ASCII) because mask_password() decodes from
            # the same encoding.
            if isinstance(stdout, six.text_type):
                stdout = stdout.encode()
            if isinstance(stderr, six.text_type):
                stderr = stderr.encode()
        else:
            # fsencode() is the reverse operation of fsdecode()
            stdout = os.fsencode(stdout)
            stderr = os.fsencode(stderr)

    return (stdout, stderr)


def get_worker_count():
    """Utility to get the default worker count.

    :returns: The number of CPUs if that can be determined, else a default
              worker count of 1 is returned.
    """
    try:
        return multiprocessing.cpu_count()
    except NotImplementedError:
        return 1


def run_cmd(cmd):
    logger.info('running cmd:%s', cmd)
    (status, output) = subprocess.getstatusoutput(cmd)
    if status != 0:
        logger.error('cmd:%s, status:%s, output:%s', cmd, status, output)
    else:
        logger.info('cmd:%s, status:%s, output:%s', cmd, status, output)
    return status, output

