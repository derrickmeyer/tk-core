# Copyright (c) 2015 Shotgun Software Inc.
#
# CONFIDENTIAL AND PROPRIETARY
#
# This work is provided "AS IS" and subject to the Shotgun Pipeline Toolkit
# Source Code License included in this distribution package. See LICENSE.
# By accessing, using, copying or modifying this work you indicate your
# agreement to the Shotgun Pipeline Toolkit Source Code License. All rights
# not expressly granted therein are reserved by Shotgun Software Inc.


class ShotgunUser(object):
    def __init__(self, host, http_proxy=None):
        self._host = host
        self._http_proxy = http_proxy

    def get_host(self):
        return self._host

    def get_http_proxy(self):
        return self._proxy

    def create_sg_connection_from_script_usern(self):
        self.__class__._not_implemented("create_sg_connection")

    def serialize(self):
        self.__class__._not_implemented("serialize")

    def get_user_info(self):
        self.__class__._not_implemented("get_user_info")

    @classmethod
    def deserialize(cls, representation):
        cls._not_implemented("deserialize")

    @classmethod
    def _not_implemented(cls, method):
        raise NotImplementedError(
            "%s.%s is not implemented." % (cls.__name__, method)
        )


class HumanUser(ShotgunUser):
    def __init__(self, host, login, session_token, http_proxy=None):
        super(HumanUser, self).__init__(host, http_proxy)

        self._login = login
        self._session_token = session_token

    def get_login(self):
        return self._login

    def create_sg_connection(self):
        from . import connection
        return connection.create_or_renew_sg_connection_from_session({
            "host": self._host,
            "http_proxy": self._http_proxy,
            "login": self._login,
            "session_token": self._session_token
        })


class ApiScriptUser(ShotgunUser):
    def __init__(self, host, api_script, api_key, http_proxy=None):
        super(ApiScriptUser, self).__init__(host, http_proxy)

        self._api_script = api_script
        self._api_key = api_key

    def create_sg_connection(self):
        from . import connection
        return connection.create_sg_connection_from_script_user({
            "host": self._host,
            "http_proxy": self._http_proxy,
            "api_script": self._api_script,
            "api_key": self._api_key
        })
