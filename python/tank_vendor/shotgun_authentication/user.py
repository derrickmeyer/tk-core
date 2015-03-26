# Copyright (c) 2015 Shotgun Software Inc.
#
# CONFIDENTIAL AND PROPRIETARY
#
# This work is provided "AS IS" and subject to the Shotgun Pipeline Toolkit
# Source Code License included in this distribution package. See LICENSE.
# By accessing, using, copying or modifying this work you indicate your
# agreement to the Shotgun Pipeline Toolkit Source Code License. All rights
# not expressly granted therein are reserved by Shotgun Software Inc.

import pickle


class ShotgunUser(object):
    def __init__(self, host, http_proxy=None):
        self._host = host
        self._http_proxy = http_proxy

    def get_host(self):
        return self._host

    def get_http_proxy(self):
        return self._http_proxy

    def create_sg_connection_from_script_usern(self):
        self.__class__._not_implemented("create_sg_connection")

    def serialize(self):
        payload = {
            "type": self.__class__.__name__,
            "data": {
                "http_proxy": self._http_proxy,
                "host": self._host
            }
        }
        self._serialize(payload["data"])
        return pickle.dumps(payload)

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


class SessionUser(ShotgunUser):
    def __init__(self, host, login, session_token, http_proxy=None):
        super(SessionUser, self).__init__(host, http_proxy)

        self._login = login
        self._session_token = session_token
        self._is_volatile = False

    def get_login(self):
        return self._login

    def get_session_token(self):
        return self._session_token

    def create_sg_connection(self):
        from . import connection
        return connection.create_or_renew_sg_connection_from_session(self)

    def set_volatile(self):
        self._is_volatile = True

    def is_volatile(self):
        return self._is_volatile

    def _serialize(self, data):
        data["login"] = self._login
        data["session_token"] = self._session_token
        data["is_volatile"] = self._is_volatile

    @staticmethod
    def deserialize(representation):
        user = SessionUser(
            host=representation["host"],
            http_proxy=representation["http_proxy"],
            login=representation["login"],
            session_token=representation["session_token"]
        )
        if representation["is_volatile"]:
            user.set_volatile()
        return user


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

    def _serialize(self, data):
        data["api_script"] = self._api_script
        data["api_key"] = self._api_key

    @staticmethod
    def deserialize(representation):
        return ApiScriptUser(**representation)


def is_script_user(sg_user):
    return isinstance(sg_user, ApiScriptUser)


def is_session_user(sg_user):
    return isinstance(sg_user, SessionUser)


__factories = {
    SessionUser.__name__: SessionUser.deserialize,
    ApiScriptUser.__name__: ApiScriptUser.deserialize
}


def deserialize(payload):
    representation = pickle.loads(payload)
    global __factories
    factory = __factories.get(representation["type"])
    if not factory:
        raise Exception("Invalid user representation: %s" % representation)
    return factory(representation["data"])
