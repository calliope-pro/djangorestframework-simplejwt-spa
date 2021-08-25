from django.conf import settings
from django.http.request import HttpRequest
from rest_framework_simplejwt.authentication import JWTAuthentication


class CustomJWTAuthentication(JWTAuthentication):
    """
    You will be authenticated with headers or cookie.
    ヘッダーでもcookieでも認証します
    """
    def authenticate(self, request: HttpRequest):
        """
        first, try headers, then try cookie.
        初めにヘッダー、次にクッキーを試します
        """
        header = self.get_header(request)
        if header is None:
            raw_token = request.COOKIES.get(settings.SIMPLE_JWT['ACCESS_TOKEN_COOKIE_KEY'], None)
        else:
            raw_token = self.get_raw_token(header)

        if raw_token is None:
            return None

        validated_token = self.get_validated_token(raw_token)

        return self.get_user(validated_token), validated_token









