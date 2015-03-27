# Copyright (c) 2015 Shotgun Software Inc.
#
# CONFIDENTIAL AND PROPRIETARY
#
# This work is provided "AS IS" and subject to the Shotgun Pipeline Toolkit
# Source Code License included in this distribution package. See LICENSE.
# By accessing, using, copying or modifying this work you indicate your
# agreement to the Shotgun Pipeline Toolkit Source Code License. All rights
# not expressly granted therein are reserved by Shotgun Software Inc.

from . import interactive_authentication
from . import authentication_manager
from . import user
from .errors import AuthenticationError
from .defaults_manager import DefaultsManager


class ShotgunAuthenticator(object):
    """
    Shotgun Authentication
    ----------------------

    This class is used to help maintain an authenticated Shotgun User session
    across multiple application launches and environments. By default, the
    library is not tied to any particular shotgun site - you can use it to
    produce an authenticated user for any site of their choosing.

    The library is essentially a series of factory methods, all returning
    ShotgunUser derived instances. This instance represents an established user
    in Shotgun. You can serialize this object and pass it around, etc. The
    create_sg_connection() method returns a shotgun instance based on the
    credentials of this user.  It wraps around a Shotgun connection and traps
    authentication errors so that whenever the Shotgun connection has expired,
    it is automatically renewed, either by the system automatically renewing it
    or by prompting the user to type in their password. Whenever QT is available,
    this is used to aid in this prompting.

    The library maintains a concept of a saved user. This is useful whenever
    you want to write code which remembers the most recent user for a given site.

    If you want to customize any of the logic of how the authentication
    stores values, handles defaults or manages the behaviour in general,
    implement an DefaultsManager class and pass it to the constructor of the
    ShotgunAuthenticator object.
    """

    def __init__(self, defaults_manager=None):
        """
        Constructor

        :param defaults_manager: A DefaultsManager object that defines the basic
                                 behaviour of this authenticator. If omitted,
                                 the default, built-in authentication will be
                                 used.
        """
        self._defaults_manager = defaults_manager or DefaultsManager()

    def get_saved_user(self):
        """
        Returns the currently saved user for the default site.

        :returns: A ShotgunUser derived object or None if no saved user has been found.
        """
        host = self._defaults_manager.get_host()
        # No default host, no so saved user can be found.
        if not host:
            return None
        return user.SessionUser.get_saved_user(
            host,
            self._defaults_manager.get_http_proxy()
        )

    def clear_saved_user(self):
        """
        Removes the saved user's credentials from disk for the default host. The
        next time the ShotgunAuthenticator.get_saved_user method is called,
        None will be returned.

        :returns: If a user was cleared, the user object is returned, None otherwise.
        """
        host = self._defaults_manager.get_host()
        # No default host, no so saved user can be found.
        if not host:
            return None
        sg_user = user.SessionUser.get_saved_user(
            host,
            self._defaults_manager.get_http_proxy()
        )
        if sg_user:
            user.SessionUser.clear_saved_user(host)
        return sg_user

    def get_user_from_prompt(self):
        """
        Display a UI prompt (QT based UI if possible but may fall back on console)

        The DefaultsManager can be used to pre-fill the host and login name.

        :raises AuthenticationError: If the user cancels the authentication process,
                                     an AuthenticationError is thrown.

        :returns: The SessionUser based on the login information provided.
        """
        host, login, session_token = interactive_authentication.authenticate(
            self._defaults_manager.get_host(),
            self._defaults_manager.get_login(),
            self._defaults_manager.get_http_proxy()
        )
        return user.SessionUser(
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
        user.save()
        return user
