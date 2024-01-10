from django.contrib.auth import logout
from rest_framework import status, exceptions
from rest_framework.authentication import get_authorization_header
from rest_framework.exceptions import APIException
from rest_framework.response import Response
from rest_framework.views import APIView

from app import authentification
from app.models import User
from app.serializers import UserSerializer
from app.authentification import Authentication


# Create your views here.
class RegisterAPIView(APIView):
    @staticmethod
    def post(request):
        serializer = UserSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(status=201)  # Return a success response with status code 201 (Created)
        else:
            return Response(serializer.errors, status=400)  # Return errors with status code 400 (Bad Request)


class LoginAPIView(APIView):
    @staticmethod
    def post(request):
        email = request.data.get('email')
        password = request.data.get('password')
        print(email, password)
        user_check = User.objects.filter(email=email).first()
        if not user_check:
            raise APIException('User not found')
        if not user_check.check_password(password):
            raise APIException('Invalid password')

        access_token = Authentication.create_token(user_check.id)
        refresh_token = Authentication.create_token(user_check.id)

        response = Response()
        response.set_cookie(key='refresh_token', value=refresh_token, httponly=True)
        response.data = {
            'token': access_token
        }

        return response


class UserAPIView(APIView):
    @staticmethod
    def get(request):
        auth = get_authorization_header(request).split()
        print(auth)
        if auth:
            token = auth[0].decode('utf-8')
            id = Authentication.decode_access_token(token)
            if id:
                user = User.objects.filter(pk=id).first()
                if user:
                    return Response(UserSerializer(user).data)
            return Response("User not found", status=status.HTTP_404_NOT_FOUND)

        raise APIException('Auth failed')


class RefreshTokenAPIView(APIView):
    @staticmethod
    def post(request):
        refresh_token = request.COOKIES.get('refresh_token')
        if refresh_token:
            try:
                id = Authentication.decode_refresh_token(refresh_token)
                access_token = Authentication.create_token(id)
                response = Response({
                    'token': access_token
                })
                return response
            except exceptions.AuthenticationFailed as e:
                # Gérer l'erreur d'authentification émise par decode_refresh_token
                return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)
        raise APIException('Refresh failed')


class LogoutAPIView(APIView):
    @staticmethod
    def post(request):
        if request.user.is_authenticated:
            logout(request)
            return Response(status=status.HTTP_200_OK)
        return Response("Not logged in", status=status.HTTP_400_BAD_REQUEST)
