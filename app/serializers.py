from rest_framework import serializers

class SignupSerializer(serializers.Serializer):
    MODULE_CHOICES = (
        ('admin', 'admin'),
        ('check_post_officer', 'check_post_officer')
    )
    name = serializers.CharField(allow_null=False, allow_blank=False)
    email = serializers.EmailField(allow_null=False, allow_blank=False)
    username = serializers.CharField(allow_null=False, allow_blank=False)
    admin_id = serializers.CharField(allow_null=False, allow_blank=False)
    password = serializers.CharField(allow_null=False, allow_blank=False)
    role = serializers.ChoiceField(allow_null=False, allow_blank=False, choices=MODULE_CHOICES)

class LoginSerializer(serializers.Serializer):
    username = serializers.CharField(allow_null=False, allow_blank=False)
    password = serializers.CharField(allow_null=False, allow_blank=False)

class ForgotPasswordSerializer(serializers.Serializer):
    old_password = serializers.CharField(allow_null=False, allow_blank=False)
    new_password = serializers.CharField(allow_null=False, allow_blank=False)

class CheckPostSerializer(serializers.Serializer):
    name = serializers.CharField(allow_null=False, allow_blank=False)
    description = serializers.CharField(allow_null=False, allow_blank=False)
    location = serializers.CharField(allow_null=False, allow_blank=False)
    latitude = serializers.CharField(allow_null=False, allow_blank=True)
    longitude = serializers.CharField(allow_null=False, allow_blank=True)
    list_of_check_post_officer = serializers.ListField(child=serializers.CharField(allow_null=False, allow_blank=False))

