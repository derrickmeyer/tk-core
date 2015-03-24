from . import interactive_authentication
from . import authentication
from . import user
from .errors import AuthenticationModuleError, AuthenticationError, AuthenticationDisabled


def get_current_user():
    info = authentication.get_connection_information()
    if authentication.is_script_user_authenticated(info):
        return user.ApiScriptUser(**info)
    elif authentication.is_human_user_authenticated(info):
        return user.HumanUser(**info)
    else:
        return None


def is_script_user(sg_user):
    return isinstance(sg_user, user.ApiScriptUser)


def is_human_user(sg_user):
    return isinstance(sg_user, user.HumanUser)


def get_user_from_prompt():
    interactive_authentication.authenticate()
    return get_current_user()


def get_user():
    sg_user = get_current_user()
    if not sg_user:
        sg_user = get_user_from_prompt()
    return sg_user


__all__ = [
    "get_current_user",
    "is_script_user",
    "is_human_user",
    "get_user_from_prompt",
    "get_user",
    "AuthenticationModuleError",
    "AuthenticationError",
    "AuthenticationDisabled"
]
