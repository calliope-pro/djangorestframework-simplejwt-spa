from django.conf import settings
from rest_framework import status
from rest_framework.response import Response
from rest_framework_simplejwt.exceptions import InvalidToken, TokenError
from rest_framework_simplejwt.serializers import (
    TokenObtainPairSerializer,
    TokenRefreshSerializer
)
from rest_framework_simplejwt.settings import api_settings
from rest_framework_simplejwt.views import TokenViewBase

from .mixin import GetTokenMixin, SetTokenMixin


class SPATokenViewBase(TokenViewBase):
    """
    This ViewBase is extended rest_framework_simplejwt.views.TokenViewBase.
    rest_framework_simplejwt.views.TokenViewBaseを継承したViewBaseです
    Validate the token data and return a just message response with HTTP_200_OK.
    クッキーのトークンデータをバリデートし、メッセージとHTTP_200_OKレスポンスを返します
    """
    success_message = 'OK'
    
    accuess_token_cookie_key = settings.SIMPLE_JWT['ACCESS_TOKEN_COOKIE_KEY']

    refresh_token_cookie_key = settings.SIMPLE_JWT['REFRESH_TOKEN_COOKIE_KEY']

    def post(self, request, *args, **kwargs):
        data = self.get_data(request)
        serializer = self.get_serializer(data=data)

        try:
            serializer.is_valid(raise_exception=True)
        except TokenError as e:
            raise InvalidToken(e.args[0])

        response = self.make_response(serializer=serializer)
        return response

    def get_data(self, request):
        access = request.COOKIES.get(self.accuess_token_cookie_key, None)
        refresh = request.COOKIES.get(self.refresh_token_cookie_key, None)

        data = {
            'access': access,
            'refresh': refresh
        }
        return data

    def make_response(self, serializer):
        response = Response(self.success_message, status=status.HTTP_200_OK)
        return response

class SPATokenView(SPATokenViewBase, GetTokenMixin):
    """
    You will use the serialized token with get_token()
    get_token()を用いてシリアライズされたトークンを用いることが出来ます
    """
    pass

class SPATokenObtainPairView(SPATokenView, SetTokenMixin):
    """
    You will set token to cookie securly
    クッキーにトークンを安全に保存します
    """
    serializer_class = TokenObtainPairSerializer

class SPATokenFirstObtainPairView(SPATokenObtainPairView):
    """
    You will set token to cookie securly with password, username, and so on
    passwordやusernameなどを用いてクッキーにトークンを安全に保存します
    """
    def get_data(self, request):
        data = request.data
        return data

class SPATokenRefreshView(SPATokenView, SetTokenMixin):
    """
    You will refresh your access token.
    アクセストークンを更新します
    if api_settings.ROTATE_REFRESH_TOKENS == True, refresh not just access token.
    もしapi_settings.ROTATE_REFRESH_TOKENS == Trueならば、リフレッシュトークンも更新します
    """
    serializer_class = TokenRefreshSerializer

    def make_response(self, serializer):
        response = super().make_response(serializer)
        token = self.get_token(serializer)
        self.set_access_token(response, token)
        if api_settings.ROTATE_REFRESH_TOKENS:
            self.set_refresh_token(response, token)
        return response
