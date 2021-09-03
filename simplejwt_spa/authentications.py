from django.conf import settings
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.exceptions import InvalidToken


class SPAJWTAuthentication(JWTAuthentication):
    """
    You will be authenticated with headers or cookie.
    ヘッダーでもcookieでも認証します
    """
    def authenticate(self, request):
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

        try:
            validated_token = self.get_validated_token(raw_token)
        except InvalidToken:
            return None

        return self.get_user(validated_token), validated_token










