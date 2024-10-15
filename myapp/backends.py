from django.contrib.auth import get_user_model
from django.contrib.auth.backends import ModelBackend

UserModel = get_user_model()

class UsernameOrEmailBackend(ModelBackend):
    def authenticate(self, request, username=None, password=None, **kwargs):
        # Check if the username input is an email
        try:
            # Try to get user by email
            user = UserModel.objects.get(email=username)
        except UserModel.DoesNotExist:
            try:
                # If no email is found, try username
                user = UserModel.objects.get(username=username)
            except UserModel.DoesNotExist:
                return None

        # Check if the password matches
        if user.check_password(password):
            return user
        return None