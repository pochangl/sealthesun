# 客製化 Authentication 以支援 windows 帳號登入
import win32security
from django.contrib.auth.backends import ModelBackend
from django.contrib.auth.models import User


class WindowsAuthBackend(ModelBackend):
    def authenticate(self, request, username=None, password=None, **kwargs):
        is_valid = is_valid_windows_credentials(username, password)
        if not is_valid:
            return None
        user, is_created = User.objects.get_or_create(username=username, password='!')

        # 預設新使用者為員工身份
        if is_created:
            user.is_staff = True
            user.save()
        return user


def is_valid_windows_credentials(username: str, password: str, domain=None) -> bool:
    # LOGON32_LOGON_INTERACTIVE is a common logon type for interactive apps.
    # LOGON32_PROVIDER_DEFAULT is the default provider.
    try:
        hUser = win32security.LogonUser(
            username,
            domain or None,  # Use None for the current domain if not specified
            password,
            win32security.LOGON32_LOGON_INTERACTIVE,
            win32security.LOGON32_PROVIDER_DEFAULT
        )
    except win32security.error:
        return False
    hUser.Close()  # Close the handle
    return True
