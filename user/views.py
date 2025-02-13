from django.shortcuts import render, redirect
from rest_framework.permissions import AllowAny
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView
from django.core.mail import send_mail
from django.utils.crypto import get_random_string
from django.contrib.auth.tokens import default_token_generator
from django.utils.http import urlsafe_base64_decode
from django.contrib.auth import get_user_model
from django.contrib import messages
from .serializers import PasswordResetSerializer, PasswordChangeSerializer, RegisterSerializer

User = get_user_model()  # Ensure CustomUser is used


def chat_view(request):
    return render(request, 'user/chat.html')


class PasswordResetView(APIView):
    def post(self, request):
        serializer = PasswordResetSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            try:
                user = User.objects.get(email=email)  # Use CustomUser model
                token = default_token_generator.make_token(user)
                reset_link = f'http://example.com/reset-password/?token={token}&uid={user.pk}'
                send_mail(
                    'Password Reset',
                    f'Click here to reset your password: {reset_link}',
                    'from@example.com',
                    [email],
                )
                return Response({"detail": "Password reset link sent."}, status=status.HTTP_200_OK)
            except User.DoesNotExist:
                return Response({"detail": "User with this email does not exist."}, status=status.HTTP_400_BAD_REQUEST)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class PasswordChangeView(APIView):
    def post(self, request):
        serializer = PasswordChangeSerializer(data=request.data)
        if serializer.is_valid():
            token = serializer.validated_data['token']
            uid = request.data.get("uid")  # Get UID from request

            try:
                uid = urlsafe_base64_decode(uid).decode()
                user = User.objects.get(pk=uid)

                if default_token_generator.check_token(user, token):
                    user.set_password(serializer.validated_data['new_password'])
                    user.save()
                    return Response({"detail": "Password has been reset successfully."}, status=status.HTTP_200_OK)
                else:
                    return Response({"detail": "Invalid or expired token."}, status=status.HTTP_400_BAD_REQUEST)
            except Exception as e:
                return Response({"detail": "Invalid token or user does not exist."}, status=status.HTTP_400_BAD_REQUEST)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


def verify_email(request):
    uid = request.GET.get('uid')
    token = request.GET.get('token')

    try:
        uid = urlsafe_base64_decode(uid).decode()
        user = User.objects.get(pk=uid)

        if default_token_generator.check_token(user, token):
            user.email_verified = True
            user.save()
            messages.success(request, 'Your email has been verified!')
            return redirect('login')  # Redirect to login or another page
        else:
            messages.error(request, 'Invalid or expired token.')
            return redirect('register')  # Redirect to registration page or error page
    except Exception as e:
        messages.error(request, f'Error: {str(e)}')
        return redirect('register')


class RegisterView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = RegisterSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            return Response({"detail": "User registered successfully."}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
