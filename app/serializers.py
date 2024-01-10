from rest_framework import serializers
from .models import User


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'username', 'email', 'password', 'bio', 'date_of_birth', 'profile_picture']
        extra_kwargs = {
            'password': {'write_only': True},  # Pour ne pas afficher le mot de passe lors de la sérialisation
        }

    def create(self, validated_data):
        password = validated_data.pop('password')
        user = self.Meta.model(**validated_data)
        if password is not None:
            user.set_password(password)  # Utilisation de la méthode set_password pour hasher le mot de passe
        user.save()
        return user
