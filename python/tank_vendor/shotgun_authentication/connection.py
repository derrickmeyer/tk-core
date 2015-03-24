# Copyright (c) 2013 Shotgun Software Inc.
#
# CONFIDENTIAL AND PROPRIETARY
#
# This work is provided "AS IS" and subject to the Shotgun Pipeline Toolkit
# Source Code License included in this distribution package. See LICENSE.
# By accessing, using, copying or modifying this work you indicate your
# agreement to the Shotgun Pipeline Toolkit Source Code License. All rights
# not expressly granted therein are reserved by Shotgun Software Inc.

"""
Shotgun connection creation.
"""

from tank_vendor.shotgun_api3 import Shotgun
from tank_vendor.shotgun_api3.lib import httplib2
from tank_vendor.shotgun_api3 import AuthenticationFault, ProtocolError

from .errors import AuthenticationError

_shotgun_instance_factory = Shotgun

# FIXME: Quick hack to easily disable logging in this module while keeping the
# code compatible. We have to disable it by default because Maya will print all out
# debug strings.
if False:
    # Configure logging
    import logging
    logger = logging.getLogger("sgtk.connection")
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


def generate_session_token(hostname, login, password, http_proxy):
    """
    Generates a session token for a given username/password on a given site.
    :param hostname: The host to connect to.
    :param login: The user to get a session for.
    :param password: Password for the user.
    :param http_proxy: Proxy to use. Can be None.
    :param shotgun_instance_factory: Shotgun API instance factory. Defaults to Shotgun.
    :returns: The generated session token for that user/password/site combo.
    :raises: TankAuthenticationError if the credentials were invalid.
    """
    try:
        # Create the instance...
        sg = _shotgun_instance_factory(
            hostname,
            login=login,
            password=password,
            http_proxy=http_proxy
        )
        # .. and generate the session token. If it throws, we have invalid credentials.
        return sg.get_session_token()
    except AuthenticationFault:
        raise AuthenticationError("Authentication failed.")
    except (ProtocolError, httplib2.ServerNotFoundError):
        raise AuthenticationError("Server %s was not found." % hostname)
    except:
        # We couldn't login, so try again.
        logging.exception("There was a problem logging in.")


def create_sg_connection_from_session(connection_information):
    """
    Tries to auto login to the site using the existing session_token that was saved.
    :param connection_information: Authentication credentials.
    :param shotgun_instance_factory: Shotgun API instance factory. Defaults to Shotgun.
    :returns: Returns a Shotgun instance.
    """
    logger.debug("Trying to create a connection from a connection information.")

    if "login" not in connection_information or "session_token" not in connection_information:
        logger.debug("Nothing was cached.")
        return None

    # Try to refresh the data
    logger.debug("Validating token.")

    sg = _validate_session_token(
        connection_information["host"],
        connection_information["session_token"],
        connection_information.get("http_proxy"),
    )
    if sg:
        logger.debug("Token is still valid!")
        return sg
    else:
        logger.debug("Failed refreshing the token.")
        return None


def _validate_session_token(host, session_token, http_proxy):
    """
    Validates the session token by attempting to an authenticated request on the site.
    :param session_token: Session token to use to connect to the host.
    :param host: Host for that session
    :param http_proxy: http_proxy to use to connect. If no proxy is required, provide None or an empty string.
    :param shotgun_instance_factory: Shotgun API instance factory.
    :returns: A Shotgun instance if the session token was valid, None otherwise.
    """
    # Connect to the site
    logger.debug("Creating shotgun instance")
    global _shotgun_instance_factory
    sg = _shotgun_instance_factory(
        host,
        session_token=session_token,
        http_proxy=http_proxy
    )
    try:
        sg.find_one("HumanUser", [])
        return sg
    except AuthenticationFault, e:
        # Session was expired.
        logger.exception(e)
        return None


def create_sg_connection_from_script_user(connection_information):
    """
    Create a Shotgun connection based on a script user.
    :param connection_information: A dictionary with keys host, api_script, api_key and an optional http_proxy.
    :returns: A Shotgun instance.
    """
    logger.debug("Creating connection with script user.")
    global _shotgun_instance_factory
    return _shotgun_instance_factory(
        connection_information["host"],
        script_name=connection_information["api_script"],
        api_key=connection_information["api_key"],
        http_proxy=connection_information.get("http_proxy", None)
    )


def create_or_renew_sg_connection_from_session(connection_information):
    """
    Creates a shotgun connection using the current session token or a new one if the old one
    expired.
    :param connection_information: A dictionary holding the connection information.
    :returns: A valid Shotgun instance.
    :raises TankAuthenticationError: If we couldn't get a valid session, a TankAuthenticationError is thrown.
    """
    logger.debug("Creating connection with cached session token.")
    # If the Shotgun login was not automated, then try to create a Shotgun
    # instance from the cached session id.
    sg = create_sg_connection_from_session(connection_information)
    # If worked, just return the result.
    if sg:
        return sg

    from . import authentication
    from . import interactive_authentication

    try:
        logger.debug("Credentials were out of date, renewing them.")
        interactive_authentication.renew_session()
        sg = create_sg_connection_from_session(
            authentication.get_connection_information()
        )
        if not sg:
            raise AuthenticationError("Authentication failed.")
    except:
        # If the authentication failed, clear the cached credentials. Only do it here instead of befor
        # the renewal otherwise multiple threads who are about to ask for credentials might clear
        # the newer credentials that another thread cached.
        authentication.clear_cached_credentials()
        raise
    return sg
