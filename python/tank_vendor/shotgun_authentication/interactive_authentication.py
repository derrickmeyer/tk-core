# Copyright (c) 2015 Shotgun Software Inc.
#
# CONFIDENTIAL AND PROPRIETARY
#
# This work is provided "AS IS" and subject to the Shotgun Pipeline Toolkit
# Source Code License included in this distribution package. See LICENSE.
# By accessing, using, copying or modifying this work you indicate your
# agreement to the Shotgun Pipeline Toolkit Source Code License. All rights
# not expressly granted therein are reserved by Shotgun Software Inc.

"""
UI and console based login for Toolkit.
"""

# Using "with" with the lock to make sure it is always released.

from __future__ import with_statement
from getpass import getpass
import threading
import os
import sys
from .errors import AuthenticationError, AuthenticationDisabled
from . import authentication
from . import connection


# FIXME: Quick hack to easily disable logging in this module while keeping the
# code compatible. We have to disable it by default because Maya will print all out
# debug strings.
if False:
    # Configure logging
    import logging
    logger = logging.getLogger("sgtk.interactive_authentication")
    logger.setLevel(logging.DEBUG)
    logger.addHandler(logging.StreamHandler())
else:
    class logger:
        @staticmethod
        def debug(*args, **kwargs):
            pass

        @staticmethod
        def info(*args, **kwargs):
            pass

        @staticmethod
        def warning(*args, **kwargs):
            pass

        @staticmethod
        def error(*args, **kwargs):
            pass

        @staticmethod
        def exception(*args, **kwargs):
            pass


def _get_qt_state():
    """
    Returns the state of Qt: the librairies available and if we have a ui or not.
    :returns: If Qt is available, a tuple of (QtCore, QtGui, has_ui_boolean_flag).
              Otherwise, (None, None, None)
    """
    try:
        from .ui.qt_abstraction import QtGui, QtCore
    except ImportError:
        return None, None, None
    return QtCore, QtGui, QtGui.QApplication.instance() is not None


def _create_invoker():
    """
    Create the object used to invoke function calls on the main thread when
    called from a different thread.

    :returns:  Invoker instance. If Qt is not available or there is no UI, no invoker will be returned.
    """
    QtCore, QtGui, has_ui = _get_qt_state()
    # If we have a ui and we're not in the main thread, we'll need to send ui requests to the
    # main thread.
    if not QtCore or not QtGui or not has_ui:
        return lambda fn, *args, **kwargs: fn(*args, **kwargs)

    class MainThreadInvoker(QtCore.QObject):
        """
        Class that allows sending message to the main thread.
        """
        def __init__(self):
            """
            Constructor.
            """
            QtCore.QObject.__init__(self)
            self._res = None
            self._exception = None
            # Make sure that the invoker is bound to the main thread
            self.moveToThread(QtGui.QApplication.instance().thread())

        def __call__(self, fn, *args, **kwargs):
            """
            Asks the MainTheadInvoker to call a function with the provided parameters in the main
            thread.
            :param fn: Function to call in the main thread.
            :param args: Array of arguments for the method.
            :param kwargs: Dictionary of named arguments for the method.
            :returns: The result from the function.
            """
            self._fn = lambda: fn(*args, **kwargs)
            self._res = None

            QtCore.QMetaObject.invokeMethod(self, "_do_invoke", QtCore.Qt.BlockingQueuedConnection)

            # If an exception has been thrown, rethrow it.
            if self._exception:
                raise self._exception
            return self._res

        @QtCore.Slot()
        def _do_invoke(self):
            """
            Execute function and return result
            """
            try:
                self._res = self._fn()
            except Exception, e:
                self._exception = e

    return MainThreadInvoker()


def get_login_name():
    """
    Retrieves the login name of the current user.
    Returns None if no login name was found
    """
    if sys.platform == "win32":
        # http://stackoverflow.com/questions/117014/how-to-retrieve-name-of-current-windows-user-ad-or-local-using-python
        return os.environ.get("USERNAME", None)
    else:
        try:
            import pwd
            pwd_entry = pwd.getpwuid(os.geteuid())
            return pwd_entry[0]
        except:
            return None


class AuthenticationHandlerBase(object):
    """
    Base class for authentication requests. It handles locking reading cached credentials
    on disk and writing newer credentials back. It also keeps track of any attempt to cancel
    authentication.
    """

    _authentication_lock = threading.Lock()
    """
    Lock the assures only one thread at a time can execute the authentication logic.
    """
    _authentication_disabled = False
    """
    Flag that keeps track if a user cancelled authentication. When the flag is raised, it will
    be impossible to authenticate again.
    """

    def authenticate(self, host, login, http_proxy):
        """
        Does the actual authentication. Prompts the user and validates the credentials.
        :param host Host to authenticate for.
        :param login: User that needs authentication.
        :param http_proxy: Proxy to connect to when authenticating.
        :raises: TankAuthenticationError If the user cancels the authentication process,
                 this exception will be thrown.
        """
        raise NotImplementedError

    def _get_session_token(self, hostname, login, password, http_proxy):
        """
        Retrieves a session token for the given credentials.
        :param hostname: The host to connect to.
        :param login: The user to get a session for.
        :param password: Password for the user.
        :param http_proxy: Proxy to use. Can be None.
        :returns: If the credentials were valid, returns a session token, otherwise returns None.
        """
        try:
            return connection.generate_session_token(hostname, login, password, http_proxy)
        except AuthenticationError:
            return None

    def raise_no_credentials_provided_error(self):
        raise AuthenticationError("No credentials provided.")


class ConsoleAuthenticationHandlerBase(AuthenticationHandlerBase):
    """
    Base class for authenticating on the console. It will take care of the credential retrieval loop,
    requesting new credentials as long as they are invalid or until the user provides the right one
    or cancels the authentication.
    """

    def authenticate(self, hostname, login, http_proxy):
        """
        Prompts the user for this password to retrieve a new session token and rewews
        the session token.
        :param hostname: Host to renew a token for.
        :param login: User to renew a token for.
        :param http_proxy: Proxy to use for the request. Can be None.
        :returns: The (session token, login user) tuple.
        """
        logger.debug("Requesting password on command line.")
        while True:
            # Get the credentials from the user
            try:
                login, password = self._get_user_credentials(hostname, login)
            except EOFError:
                # Insert a \n on the current line so the print is displayed on a new time.
                print
                self.raise_no_credentials_provided_error()

            session_token = self._get_session_token(hostname, login, password, http_proxy)
            if session_token:
                return hostname, login, session_token

    def _get_user_credentials(self, hostname, login):
        """
        Prompts the user for his credentials.
        :param host Host to authenticate for.
        :param login: User that needs authentication.
        :param http_proxy: Proxy to connect to when authenticating.
        :raises: TankAuthenticationError If the user cancels the authentication process,
                 this exception will be thrown.
        """
        raise NotImplementedError

    def _get_password(self):
        """
        Prompts the user for his password. The password will not be visible on the console.
        :raises: TankAuthenticationError If the user enters an empty password, the exception
                                         will be thrown.
        """
        password = getpass("Password (empty to abort): ")
        if not password:
            self.raise_no_credentials_provided_error()
        return password

    def _get_keyboard_input(self, label, default_value=""):
        """
        Queries for keyboard input.
        :param label: The name of the input we require.
        :param default_value: The value to use if the user has entered no input.
        :returns: The user input or default_value if nothing was entered.
        """
        text = label
        if default_value:
            text += " [%s]" % default_value
        text += ": "
        user_input = None
        while not user_input:
            user_input = raw_input(text) or default_value
        return user_input

    def _get_session_token(self, hostname, login, password, http_proxy):
        """
        Retrieves a session token for the given credentials.
        :param hostname: The host to connect to.
        :param login: The user to get a session for.
        :param password: Password for the user.
        :param http_proxy: Proxy to use. Can be None.
        :returns: If the credentials were valid, returns a session token, otherwise returns None.
        """
        token = super(ConsoleAuthenticationHandlerBase, self)._get_session_token(hostname, login, password, http_proxy)
        if not token:
            print "Login failed."
        return token
        try:
            return connection.generate_session_token(hostname, login, password, http_proxy)
        except AuthenticationError:
            return None


class ConsoleRenewSessionHandler(ConsoleAuthenticationHandlerBase):
    """
    Handles session renewal. Prompts for the user's password.
    """
    def _get_user_credentials(self, hostname, login):
        """
        Reads the user password from the keyboard.
        :param hostname: Name of the host we will be logging on.
        :param login: Current user
        :returns: The user's password.
        """
        print "%s, your current session has expired." % login
        print "Please enter your password to renew your session for %s" % hostname
        return login, self._get_password()


class ConsoleLoginHandler(ConsoleAuthenticationHandlerBase):
    """
    Handles username/password authentication.
    """
    def _get_user_credentials(self, hostname, login):
        """
        Reads the user credentials from the keyboard.
        :param hostname: Name of the host we will be logging on.
        :param login: Default value for the login.
        :returns: A tuple of (login, password) strings.
        """
        print "Please enter your login credentials for %s" % hostname
        login = self._get_keyboard_input("Login", login)
        password = self._get_password()
        return login, password


class UiAuthenticationHandler(AuthenticationHandlerBase):
    """
    Handles ui based authentication.
    """

    def __init__(self, gui_launcher, is_session_renewal):
        """
        Creates the UiAuthenticationHandler object.
        :param is_session_renewal: Boolean indicating if we are renewing a session. True if we are, False otherwise.
        """
        self._is_session_renewal = is_session_renewal
        self._gui_launcher = gui_launcher

    def authenticate(self, hostname, login, http_proxy):
        """
        Pops a dialog that asks for the hostname, login and password of the user. If there is a current
        engine, it will run the code in the main thread.
        :param hostname: Host to display in the dialog.
        :param login: login to display in the dialog.
        :param http_proxy: Proxy server to use when validating credentials. Can be None.
        :returns: A tuple of (hostname, login, session_token)
        """
        from .ui import login_dialog

        if self._is_session_renewal:
            logger.debug("Requesting password in a dialog.")
        else:
            logger.debug("Requesting username and password in a dialog.")

        def _process_ui():
            dlg = login_dialog.LoginDialog(
                "Shotgun Login",
                is_session_renewal=self._is_session_renewal,
                hostname=hostname,
                login=login,
                http_proxy=http_proxy
            )
            return dlg.result()

        result = self._gui_launcher(_process_ui)

        if not result:
            self.raise_no_credentials_provided_error()
        return result


def _authentication_loop(credentials_handler, force_authentication=False):
    """
    Common login logic, regardless of how we are actually logging in. It will first try to reuse
    any existing session and if that fails then it will ask for credentials and upon success
    the credentials will be cached.
    :param force_authentication: Forces the authentication.
    :raises: TankAuthenticationError Thrown if the authentication is cancelled.
    :raises: TankAuthenticationDisabled Thrown if authentication was cancelled before.
    """
    logger.debug("About to take the authentication lock.")
    with AuthenticationHandlerBase._authentication_lock:
        logger.debug("Took the authentication lock.")
        connection_information = authentication.get_connection_information()

        # If we are authenticated as a script user, there's no point trying to authenticate
        # as a human user, it has precedence.
        if authentication.is_script_user_authenticated(connection_information):
            return
        # If we already have a cached session on file, we'll consider ourselves as authenticated,
        # unless someone is forcing authentication (in the case of a renew)
        elif authentication.is_human_user_authenticated(connection_information) and not force_authentication:
            return
        # If somebody disabled authentication, we're done here as well.
        elif AuthenticationHandlerBase._authentication_disabled:
            raise AuthenticationDisabled()

        try:
            logger.debug("Not authenticated, requesting user input.")
            # Do the actually credentials prompting and authenticating.
            hostname, login, session_token = credentials_handler.authenticate(
                connection_information["host"],
                connection_information.get("login", get_login_name()),
                connection_information.get("http_proxy")
            )
        except AuthenticationError:
            AuthenticationHandlerBase._authentication_disabled = True
            logger.debug("Authentication cancelled, disabling authentication.")
            raise

        logger.debug("Login successful!")

        # Cache the credentials so subsequent session based logins can reuse the session id.
        authentication.cache_connection_information(hostname, login, session_token)


def _ui_renew_session(gui_launcher=None):
    """
    Prompts the user to enter his password in a dialog to retrieve a new session token.
    :param gui_launcher: Function that will launch the gui. The function will be receiving a callable object
                         which will take care of invoking the gui in the right thread. If None, the gui will
                         be launched in the current thread.
    """
    _authentication_loop(UiAuthenticationHandler(
        is_session_renewal=True,
        gui_launcher=gui_launcher or (lambda func: func())
    ), force_authentication=True)


def _ui_authenticate(gui_launcher=None):
    """
    Authenticates the current process. Authentication can be done through script user authentication
    or human user authentication. If doing human user authentication and there is no session cached, a
    dialgo asking for user credentials will appear.
    :param gui_launcher: Function that will launch the gui. The function will be receiving a callable object
                         which will take care of invoking the gui in the right thread. If None, the gui will
                         be launched in the current thread.
    """
    _authentication_loop(UiAuthenticationHandler(
        is_session_renewal=False,
        gui_launcher=gui_launcher or (lambda func: func())
    ))


def _console_renew_session():
    """
    Prompts the user to enter his password on the command line to retrieve a new session token.
    """
    _authentication_loop(ConsoleRenewSessionHandler(), force_authentication=True)


def _console_authenticate():
    """
    Authenticates the current process. Authentication can be done through script user authentication
    or human user authentication. If doing human user authentication and there is no session cached, the
    user credentials will be retrieved from the console.
    """
    _authentication_loop(ConsoleLoginHandler())


def console_logout():
    """
    Logs out of the currently cached session and prints whether it worked or not.
    """
    connection_info = authentication.logout()
    if connection_info:
        print "Succesfully logged out of", connection_info["host"]
    else:
        print "Not logged in."


def renew_session():
    QtCore, QtGui, has_ui = _get_qt_state()
    # If we have a gui, we need gui based authentication
    if has_ui:
        # If we are renewing for a background thread, use the invoker
        if QtCore.QThread.currentThread() != QtGui.QApplication.instance().thread():
            _ui_renew_session(_create_invoker())
        else:
            _ui_renew_session()
    else:
        _console_renew_session()


def authenticate():
    QtCore, QtGui, has_ui = _get_qt_state()
    # If we have a gui, we need gui based authentication
    if has_ui:
        # If we are renewing for a background thread, use the invoker
        if QtCore.QThread.currentThread() != QtGui.QApplication.instance().thread():
            _ui_authenticate(_create_invoker())
        else:
            _ui_authenticate()
    else:
        _console_authenticate()
