from django.urls import path, include
from . import views

urlpatterns = [
    path('creation/', views.UserCreationAPI.as_view()),
    path('password/', views.PasswordSet.as_view()),
    path('token/', views.GenerateToken.as_view())
]
