from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import AuthenticationFailed
from .models import TechnetionToken, BusinessToken

class TechnetionTokenAuthentication(BaseAuthentication):
    def authenticate(self, request):
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Token '):
            return None  # No token provided

        token_key = auth_header.split(' ')[1]  # Extract the token key
        try:
            token = TechnetionToken.objects.get(key=token_key)
            return (token.technician, None)  # Return the technician and no credentials
        except TechnetionToken.DoesNotExist:
            raise AuthenticationFailed('Invalid token')


class BusinessTokenAuthentication(BaseAuthentication):
    def authenticate(self, request):
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Token '):
            return None  # No token provided

        token_key = auth_header.split(' ')[1]  # Extract the token key
        try:
            token = BusinessToken.objects.get(key=token_key)
            return (token.business, None)  # Return the business and no credentials
        except BusinessToken.DoesNotExist:
            raise AuthenticationFailed('Invalid token')