from abc import ABC

from rest_framework import serializers
from django.contrib.auth.models import User


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['username', 'email', 'first_name', 'last_name']


class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField(max_length=255, write_only=True)
    password = serializers.CharField(max_length=128, write_only=True)
    session_id = serializers.UUIDField(read_only=True)
