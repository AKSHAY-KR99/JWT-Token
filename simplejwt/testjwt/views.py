from datetime import timedelta

from django.contrib.auth import authenticate
from django.contrib.auth.models import User, update_last_login
from django.utils import timezone
from rest_framework import status
from django.core.exceptions import ValidationError
from rest_framework.generics import get_object_or_404
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken

from testjwt.models import LoginTrackerModel
from testjwt.serializers import UserSerializer
from testjwt.validators import validate_password


class UserCreationAPI(APIView):

    def post(self, request, *args, **kwargs):
        required_fields = ['username', 'email', 'first_name', 'last_name']
        for fields in required_fields:
            if fields not in request.data:
                return Response({'detail': f'please provide {fields}'}, status=status.HTTP_400_BAD_REQUEST)
        user_serializer = UserSerializer(data=request.data)
        user_serializer.is_valid(raise_exception=True)
        user_serializer.save()
        return Response({'message': 'User Created.', 'data': user_serializer.data}, status=status.HTTP_201_CREATED)


class PasswordSet(APIView):

    def post(self, request):
        if 'username' not in request.data or 'password' not in request.data:
            return Response({'detail': 'please provide username/password.'}, status=status.HTTP_400_BAD_REQUEST)
        try:
            validate_password(password=request.data['password'])
        except ValidationError as error:
            return Response({'detail': error}, status=status.HTTP_400_BAD_REQUEST)

        user_data = get_object_or_404(User, username=request.data['username'])
        user_data.set_password(request.data['password'])
        login_tracker = LoginTrackerModel.objects.create(user=user_data)
        session_id = login_tracker.session_id
        return Response({'message': f'Password set for {user_data.username}',
                         'session_id': session_id}, status=status.HTTP_200_OK)


class GenerateToken(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        if 'session_id' not in request.data or 'password' not in request.data:
            return Response({'detail': 'Please provide login credentials'}, status=status.HTTP_400_BAD_REQUEST)
        time_threshold = timezone.now() - timedelta(minutes=5)
        tracker_object = LoginTrackerModel.objects.filter(session_id=request.data['session_id'],
                                                          date_created__gte=time_threshold)
        if tracker_object.exists():
            user_object = User.objects.get(id=tracker_object[0].user.id)
            print(user_object.id)
            user = authenticate(request, username=user_object.username, password=request.data['password'])
            print('user >> ', user)
            if user is not None:
                refresh = RefreshToken.for_user(user)
                update_last_login(None, user)
                return Response({'message': 'User authentication completed',
                                 'access_token': str(refresh.access_token),
                                 'refresh_token': str(refresh)}, status=status.HTTP_200_OK)
            else:
                return Response({'detail': 'Enter user credentials are invalid.'}, status=status.HTTP_401_UNAUTHORIZED)
        else:
            return Response({'detail': 'session id entered not correct or it has expired.'},
                            status=status.HTTP_401_UNAUTHORIZED)