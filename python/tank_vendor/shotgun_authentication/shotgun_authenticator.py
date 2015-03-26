from . import interactive_authentication
from . import authentication
from . import authentication_manager
from . import user
from .errors import AuthenticationModuleError, AuthenticationError, AuthenticationDisabled


class ShotgunAuthenticator(object):
    """
    Shotgun Authentication
    ----------------------

    This class is used to help maintain an authenticated Shotgun User session
    across multiple application launches and environments. By default, the library is not tied
    to any particular shotgun site - you can use it to produce an authenticated
    user for any site of their choosing.

    The library is essentially a series of factory methods, all returning
    AuthenticatedUser objects. This object represents an established user
    in Shotgun. You can serialize this object and pass it round etc. The
    get_sg_connection() method returns a shotgun instance based on the
    credentials of this user.  It wraps around a Shotgun connection and traps
    authentication errors so that whenever the shotgun connection has expired,
    it is automatically renewed, either by the system automatically renewing it
    or by prompting the user to type in their password. Whenever QT is available,
    this is used to aid in this prompting.

    The library maintains a concept of a saved user. This is useful whenever
    you want to write code which remembers the most recent user.

    If you want to customize any of the logic of how the authentication
    stores values, handles defaults or manages the behaviour in general,
    implement an AuthenticationHandler class and set this via the
    set_authentication_handler() method.
    """

    def __init__(self, defaults_manager):
        """
        Constructor

        :param defaults_manager: An AuthenticationHandler object that
                                 defines the basic behaviour of this
                                 authenticator. If omitted, the default,
                                 built-in authentication will be used.
        """
        self._defaults_manager = defaults_manager

    def get_saved_user(self):
        """
        Returns the currently saved user.

        :returns: AuthenticatedUser object or None if no saved user has been defined.
        """
        host = self._defaults_manager.get_host()
        credentials = authentication_manager._get_login_info(host)
        if credentials:
            return user.HumanUser(
                host=host,
                http_proxy=self._defaults_manager.get_http_proxy(),
                **credentials
            )
        else:
            return None

    def save_user(self, user):
        """
        Sets the saved user.

        :param user: Specifying a user to be the current user.
        """
        if is_script_user(user):
            raise AuthenticationError("Can't save ApiScriptUser in session cache.")
        authentication_manager._cache_session_data(
            user.get_host(),
            user.get_login(),
            user.get_session_token()
        )

    def clear_saved_user(self):
        """
        Removes the currently saved user. The next time get_saved_user() is called,
        None will be returned.
        """
        authentication_manager._delete_session_data(self._defaults_manager.get_host())

    def get_user_from_prompt(self):
        """
        Display a UI prompt (QT based UI if possible but may fall back on console)

        If a saved user exists, this will be used to populate defaults in the UI.
        Default values can also be controlled by custom authentication handler.

        :returns: AuthenticatedUser object or None if the user cancelled.
        """
        host, login, session_token = interactive_authentication.ConsoleLoginHandler().authenticate(
            self._defaults_manager.get_host(),
            self._defaults_manager.get_login(),
            self._defaults_manager.get_http_proxy()
        )
        return user.HumanUser(
            host=host,
            http_proxy=self._defaults_manager.get_http_proxy(),
            login=login, session_token=session_token
        )

    def create_human_user(self, login, session_token=None, password=None, host=None):
        """
        Create an AuthenticatedUser given a set of human user credentials.
        Either a password or session token must be supplied.

        :param login: Shotgun user login
        :param session_token: Shotgun session token
        :param password: Shotgun password
        :param host: Shotgun host to log in to. Depending on how the authenticator
                     is configured, this may be required or optional. If the
                     authenticator is configured so that it is connected to
                     a specific shotgun site, this parameter is not necessary, however
                     if it is configured by
        """
        pass

    def create_script_user(self, script_user, script_key, host=None):
        """
        Create an AuthenticatedUser given a set of script credentials.

        :param script_user: Shotgun script user
        :param script_key: Shotgun script key
        :param host: Shotgun host to log in to. Depending on how the authenticator
                     is configured, this may be required or optional. If the
                     authenticator is configured so that it is connected to
                     a specific shotgun site, this parameter is not necessary, however
                     if it is configured by
        """
        pass

    def get_user(self):
        user = self.get_saved_user() or self._defaults_manager.get_user()
        if user:
            return user
        user = self.get_user_from_prompt()
        self.save_user(user)
        return user
