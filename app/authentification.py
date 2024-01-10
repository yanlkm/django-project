
import jwt
from datetime import datetime, timedelta

from rest_framework import exceptions


class Authentication:
    # Clé secrète pour signer les tokens
    SECRET_KEY = 'clé_secrete'

    @staticmethod
    def create_token(user_id):
        # Date actuelle
        now = datetime.utcnow()
        # Date d'expiration du token (1 heure)
        expire_time = now + timedelta(hours=1)

        # Création du token d'accès avec une durée de vie d'une heure
        payload = {
            'user_id': user_id,
            'exp': expire_time,
            'iat': now
        }
        access_token = jwt.encode(payload, Authentication.SECRET_KEY, algorithm='HS256')
        return access_token

    @staticmethod
    def refresh_token(user_id):
        # Date actuelle
        now = datetime.utcnow()
        # Date d'expiration du token de rafraîchissement ( 7 jours)
        expire_time = now + timedelta(days=7)

        # Création du token de rafraîchissement avec une durée de vie de 7 jours
        payload = {
            'user_id': user_id,
            'exp': expire_time,
            'iat': now
        }
        refresh_token = jwt.encode(payload, Authentication.SECRET_KEY, algorithm='HS256')
        return refresh_token

    @staticmethod
    def decode_access_token(access_token):
        try:
            decoded = jwt.decode(access_token, Authentication.SECRET_KEY, algorithms=['HS256'])
            return decoded.get('user_id')
        except jwt.ExpiredSignatureError:
            # Gérer une signature expirée
            return exceptions.AuthenticationFailed('expired token')
        except jwt.InvalidTokenError:
            # Gérer une signature invalide
            return exceptions.AuthenticationFailed('unrecognized token')

    @staticmethod
    def decode_refresh_token(refresh_token):
        try:
            decoded = jwt.decode(refresh_token, Authentication.SECRET_KEY, algorithms=['HS256'])
            return decoded.get('user_id')
        except jwt.ExpiredSignatureError:
            # Gérer une signature expirée
            return exceptions.AuthenticationFailed('expired token')
        except jwt.InvalidTokenError:
            # Gérer une signature invalide
            return exceptions.AuthenticationFailed('unrecognized token')
