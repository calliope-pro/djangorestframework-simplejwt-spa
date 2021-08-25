from django.conf import settings


class SetAccessTokenMixin:
    """
    Mixin to set access token to cookie securly.
    アクセストークンをクッキーに安全に保存します
    """
    accuess_token_lifetime = settings.SIMPLE_JWT['ACCESS_TOKEN_LIFETIME']

    auth_cookie_secure = settings.SIMPLE_JWT['AUTH_COOKIE_SECURE']
    auth_cookie_samesite = settings.SIMPLE_JWT['AUTH_COOKIE_SAMESITE']

    def set_access_token(self, response, token):
        """
        SECURITY WARNING: set up httponly=True!
        警告: httponly=Trueに設定してください
        You can change the arguments in the config.settings.py
        config.settings.pyにて引数を変更できます
        """
        response.set_cookie(
            key=self.accuess_token_cookie_key,
            value=token['access'],
            expires=self.accuess_token_lifetime,
            secure=self.auth_cookie_secure,
            samesite=self.auth_cookie_samesite,
            httponly=True,
        )

    def make_response(self, serializer):
        response = super().make_response(serializer)
        token = self.get_token(serializer)
        self.set_access_token(response, token)
        return response


class SetRefreshTokenMixin:
    """
    Mixin to set refresh token to cookie securly.
    リフレッシュトークンをクッキーに安全に保存します
    """
    refresh_token_lifetime = settings.SIMPLE_JWT['REFRESH_TOKEN_LIFETIME']

    auth_cookie_secure = settings.SIMPLE_JWT['AUTH_COOKIE_SECURE']
    auth_cookie_samesite = settings.SIMPLE_JWT['AUTH_COOKIE_SAMESITE']

    def set_refresh_token(self, response, token):
        """
        SECURITY WARNING: set up httponly=True!
        警告: httponly=Trueに設定してください
        You can change the arguments in the config.settings.py
        config.settings.pyにて引数を変更できます
        """
        response.set_cookie(
            key=self.refresh_token_cookie_key,
            value=token['refresh'],
            expires=self.refresh_token_lifetime,
            secure=self.auth_cookie_secure,
            samesite=self.auth_cookie_samesite,
            httponly=True,
        )

    def make_response(self, serializer):
        response = super().make_response(serializer)
        token = self.get_token(serializer)
        self.set_refresh_token(response, token)
        return response


class SetTokenMixin(SetAccessTokenMixin, SetRefreshTokenMixin):
    """
    Mixin to set both access and refresh token to cookie securly.
    アクセス・リフレッシュトークン共にクッキーに安全に保存します
    """
    def make_response(self, serializer):
        response = super().make_response(serializer)
        token = self.get_token(serializer)
        self.set_access_token(response, token)
        self.set_refresh_token(response, token)
        return response
