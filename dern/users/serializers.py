from rest_framework import serializers
from django.contrib.auth import authenticate
from .models import Users, Technetion, Requests, History
from django.contrib.auth.hashers import make_password
from .models import Business


# User Signup Serializer
class UserSignupSerializer(serializers.ModelSerializer):

    class Meta:
        model = Users
        fields = ['username', 'email', 'password']
        extra_kwargs = {'password': {'write_only': True}}

    def create(self, validated_data):
        user = Users.objects.create_user(
            username=validated_data['username'],
            email=validated_data['email'],
            password=validated_data['password']
        )
        return user

# User Login Serializer
class UserLoginSerializer(serializers.Serializer):
    username = serializers.CharField()
    password = serializers.CharField(write_only=True)

    def validate(self, data):
        user = authenticate(username=data['username'], password=data['password'])
        if user and user.is_active:
            return {'user': user}
        raise serializers.ValidationError("Invalid credentials")

# Technician Signup Serializer
class TechnetionSignupSerializer(serializers.ModelSerializer):
    class Meta:
        model = Technetion
        fields = ['id','name', 'email', 'password', 'role']
        extra_kwargs = {'password': {'write_only': True}}

    def create(self, validated_data):
        validated_data['password'] = make_password(validated_data['password'])  # Hash the password
        technician = Technetion.objects.create(**validated_data)
        return technician

# Requests Serializer
class RequestsSerializer(serializers.ModelSerializer):
    class Meta:
        model = Requests
        fields = [
            'id', 'user', 'business', 'description', 'pickup_address', 'when_available',
            'is_done', 'technician', 'repair_completion_date', 'email', 'phone',
            'request_type', 'request_state'  # Add request_state here
        ]
        read_only_fields = ['user', 'business', 'technician', 'repair_completion_date', 'request_state']

    def validate(self, data):
        # Ensure at least one of email or phone is provided for business-created requests
        if not data.get('email') and not data.get('phone'):
            raise serializers.ValidationError("At least one of email or phone is required.")
        return data

    def create(self, validated_data):
        # Automatically assign the request type based on the authenticated user
        if isinstance(self.context['request'].user, Business):
            validated_data['request_type'] = 'business'
            validated_data['business'] = self.context['request'].user
        else:
            validated_data['request_type'] = 'user'
            validated_data['user'] = self.context['request'].user
        return super().create(validated_data)


class HistorySerializer(serializers.ModelSerializer):
    request_type = serializers.CharField(source='request.request_type', read_only=True)  # Get request_type from the related Requests model

    class Meta:
        model = History
        fields = ['id', 'user', 'business', 'request', 'completion_date', 'request_type']
        

class BusinessSignupSerializer(serializers.ModelSerializer):
    class Meta:
        model = Business
        fields = ['business_name', 'business_address', 'business_email', 'business_phone', 'password']
        extra_kwargs = {'password': {'write_only': True}}

    def create(self, validated_data):
        business = Business.objects.create(
            business_name=validated_data['business_name'],
            business_address=validated_data['business_address'],
            business_email=validated_data['business_email'],
            business_phone=validated_data['business_phone']
        )
        business.set_password(validated_data['password'])
        business.save()
        return business

class BusinessLoginSerializer(serializers.Serializer):
    business_email = serializers.EmailField()
    password = serializers.CharField(write_only=True)

    def validate(self, data):
        business_email = data.get('business_email')
        password = data.get('password')

        try:
            business = Business.objects.get(business_email=business_email)
        except Business.DoesNotExist:
            raise serializers.ValidationError("Invalid credentials")

        if not business.check_password(password):
            raise serializers.ValidationError("Invalid credentials")

        if not business.is_active:
            raise serializers.ValidationError("Business account is inactive")

        return {'business': business}