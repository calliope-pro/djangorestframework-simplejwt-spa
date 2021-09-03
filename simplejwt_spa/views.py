from django.conf import settings
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.exceptions import InvalidToken, TokenError
from rest_framework_simplejwt.serializers import (
    TokenObtainPairSerializer,
    TokenRefreshSerializer
)
from rest_framework_simplejwt.settings import api_settings
from rest_framework_simplejwt.views import TokenViewBase

from .authentications import SPAJWTAuthentication
from .mixin import SetTokenMixin


class SPATokenViewBase(TokenViewBase):
    """
    This ViewBase is extended rest_framework_simplejwt.views.TokenViewBase.
    rest_framework_simplejwt.views.TokenViewBaseを継承したViewBaseです
    You have to either include a serializer_class attribute, or override the get_serializer_class() method.
    serializer_class属性、またはget_serializer_class()を設定してください
    Validate the token data and return a just message response with HTTP_200_OK when validated successfully.
    クッキーのトークンデータをバリデートし、成功したらメッセージとHTTP_200_OKレスポンスを返します
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
        data = request.data
        return data

    def get_token(self, serializer):
        token = serializer.validated_data
        return token

    def make_response(self, serializer):
        response = Response(self.success_message, status=status.HTTP_200_OK)
        return response


class SPATokenObtainPairView(SetTokenMixin, SPATokenViewBase):
    """
    You will set token to cookie securly.
    クッキーにトークンを安全に保存します
    """
    serializer_class = TokenObtainPairSerializer


class SPATokenRefreshView(SetTokenMixin, SPATokenViewBase):
    """
    You will refresh your access token.
    アクセストークンを更新します
    if api_settings.ROTATE_REFRESH_TOKENS == True, refresh not just access token.
    もしapi_settings.ROTATE_REFRESH_TOKENS == Trueならば、リフレッシュトークンも更新します
    """
    serializer_class = TokenRefreshSerializer

    def get_data(self, request):
        access = request.COOKIES.get(self.accuess_token_cookie_key, None)
        refresh = request.COOKIES.get(self.refresh_token_cookie_key, None)

        data = {
            'access': access,
            'refresh': refresh
        }
        return data

    def make_response(self, serializer):
        response = super().make_response(serializer)
        token = self.get_token(serializer)
        self.set_access_token(response, token)
        if api_settings.ROTATE_REFRESH_TOKENS:
            self.set_refresh_token(response, token)
        return response


class SPAVerifyAuthView(APIView):
    """
    You will verify if token is valid.
    tokenが有効か検証します
    """
    authentication_classes = (SPAJWTAuthentication, )
    permission_classes = (IsAuthenticated, )

    def get(self, request, *args, **kwargs):
        return Response('OK', status=status.HTTP_200_OK)

    def post(self, request, *args, **kwargs):
        return Response('OK', status=status.HTTP_200_OK)
