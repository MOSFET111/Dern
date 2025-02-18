from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from django.contrib.auth.hashers import check_password 
from django.contrib.auth.models import AnonymousUser
import secrets
from django.utils import timezone
from rest_framework.permissions import AllowAny
from rest_framework.authtoken.models import Token
from .authentication import TechnetionTokenAuthentication
from .authentication import BusinessTokenAuthentication
from .serializers import BusinessSignupSerializer, BusinessLoginSerializer
from .models import Users, Technetion, Requests, History,Business, BusinessToken, TechnetionToken
from .serializers import (
    UserSignupSerializer,
    UserLoginSerializer,
    TechnetionSignupSerializer,
    RequestsSerializer,
    HistorySerializer
)

# User Make Request
# User Make Request
class CreateUserRequestView(APIView):
    permission_classes = [IsAuthenticated]  # Ensure the user is authenticated

    def post(self, request):
        # Ensure the request is authenticated
        if not request.user or isinstance(request.user, AnonymousUser):
            return Response({"detail": "Authentication credentials were not provided."}, status=status.HTTP_401_UNAUTHORIZED)
        
        serializer = RequestsSerializer(data=request.data, context={'request': request})
        if serializer.is_valid():
            # Automatically assign the authenticated user to the request
            created_request = serializer.save(user=request.user)
            return Response({"message": "Request created successfully", "request_id": created_request.id}, status=status.HTTP_201_CREATED)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

# User Signup
class UserSignup(APIView):
    permission_classes = [AllowAny] 
    def post(self, request):
        serializer = UserSignupSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({"message": "User created successfully"}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

# User Login
class UserLoginView(APIView):
    permission_classes = [AllowAny]
    def post(self, request):
        serializer = UserLoginSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.validated_data['user']
            token, _ = Token.objects.get_or_create(user=user)
            return Response({
                "message": "Login successful",
                "username": user.username,
                "token": token.key
            }, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

#use logout
class LogoutView(APIView):
    permission_classes = [IsAuthenticated]  # Ensure the user is authenticated

    def post(self, request):
        # Delete the user's token to log them out
        request.user.auth_token.delete()
        return Response({"message": "Logout successful"}, status=status.HTTP_200_OK)


class TechnicianLogoutView(APIView):
    authentication_classes = [TechnetionTokenAuthentication]  # Use custom authentication
    permission_classes = [IsAuthenticated]  # Ensure the user is authenticated

    def post(self, request):
        # Get the technician's token
        try:
            token = TechnetionToken.objects.get(technician=request.user)
            token.delete()  # Delete the token to log out the technician
            return Response({"message": "Logout successful for technician"}, status=status.HTTP_200_OK)
        except TechnetionToken.DoesNotExist:
            return Response({"error": "Invalid token"}, status=status.HTTP_400_BAD_REQUEST)

# Technician Signup
from rest_framework.permissions import AllowAny  # Add this import

# Technician Signup
class TechnetionSignupView(APIView):
    permission_classes = [AllowAny]  # Allow anyone to access this view

    def post(self, request):
        serializer = TechnetionSignupSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({"message": "Technician account created successfully"}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class TechnetionLoginView(APIView):
    permission_classes = [AllowAny]  # Allow anyone to access this view

    def post(self, request):
        email = request.data.get('email')
        password = request.data.get('password')

        if not email or not password:
            return Response({"error": "Email and password are required"}, status=status.HTTP_400_BAD_REQUEST)

        try:
            technician = Technetion.objects.get(email=email)
        except Technetion.DoesNotExist:
            return Response({"error": "Invalid credentials"}, status=status.HTTP_400_BAD_REQUEST)

        # Check password (hashed comparison)
        if check_password(password, technician.password):
            # Generate or retrieve the token
            token, created = TechnetionToken.objects.get_or_create(
                technician=technician,
                defaults={'key': secrets.token_hex(20)}  # Generate a random token
            )

            return Response({
                "message": "Login successful",
                "token": token.key,
                "technician": {
                    "id": technician.id,
                    "name": technician.name,
                    "email": technician.email,
                    "role": technician.role
                }
            }, status=status.HTTP_200_OK)
        else:
            return Response({"error": "Invalid credentials"}, status=status.HTTP_400_BAD_REQUEST)



# Admin View Requests
class AdminViewRequestsView(APIView):
    authentication_classes = [TechnetionTokenAuthentication]  # Use custom authentication
    permission_classes = [IsAuthenticated]

    def get(self, request):
        if request.user.role != 'admin':  # request.user will be the Technetion instance
            return Response({"error": "Unauthorized"}, status=status.HTTP_403_FORBIDDEN)

        requests = Requests.objects.all()
        serializer = RequestsSerializer(requests, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)
# View for all requests with 'pending' state
class PendingRequestsView(APIView):
    authentication_classes = [TechnetionTokenAuthentication]  # Use custom authentication
    permission_classes = [IsAuthenticated]

    def get(self, request):
        if request.user.role != 'admin':  # Ensure the user is an admin
            return Response({"error": "Unauthorized"}, status=status.HTTP_403_FORBIDDEN)

        # Filter requests by 'pending' state
        pending_requests = Requests.objects.filter(request_state='pending')
        serializer = RequestsSerializer(pending_requests, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

# View for all requests with 'work_on_progress' state
class WorkOnProgressRequestsView(APIView):
    authentication_classes = [TechnetionTokenAuthentication]  # Use custom authentication
    permission_classes = [IsAuthenticated]

    def get(self, request):
        if request.user.role != 'admin':  # Ensure the user is an admin
            return Response({"error": "Unauthorized"}, status=status.HTTP_403_FORBIDDEN)

        # Filter requests by 'work_on_progress' state
        in_progress_requests = Requests.objects.filter(request_state='on_progress')
        serializer = RequestsSerializer(in_progress_requests, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)


class AdminViewTechniciansView(APIView):
    authentication_classes = [TechnetionTokenAuthentication]  # Use custom authentication
    permission_classes = [IsAuthenticated]  # Ensure the user is authenticated

    def get(self, request):
        # Check if the user is an admin
        if request.user.role != 'admin':
            return Response({"error": "Unauthorized. Only admins can access this view."}, status=status.HTTP_403_FORBIDDEN)

        # Fetch all technicians (both admins and regular technicians)
        technicians = Technetion.objects.all()

        # Serialize the data
        serializer = TechnetionSignupSerializer(technicians, many=True)

        return Response(serializer.data, status=status.HTTP_200_OK)

# View for technicians linked to a request
class TechniciansLinkedToRequestView(APIView):
    authentication_classes = [TechnetionTokenAuthentication]  # Use custom authentication
    permission_classes = [IsAuthenticated]  # Ensure the user is authenticated

    def get(self, request):
        # Check if the user is an admin
        if request.user.role != 'admin':
            return Response({"error": "Unauthorized. Only admins can access this view."}, status=status.HTTP_403_FORBIDDEN)

        # Fetch technicians who are linked to at least one request
        technicians = Technetion.objects.filter(assigned_requests__isnull=False).distinct()

        # Serialize the data
        serializer = TechnetionSignupSerializer(technicians, many=True)

        return Response(serializer.data, status=status.HTTP_200_OK)


# View for technicians not linked to any request
class TechniciansNotLinkedToRequestView(APIView):
    authentication_classes = [TechnetionTokenAuthentication]  # Use custom authentication
    permission_classes = [IsAuthenticated]  # Ensure the user is authenticated

    def get(self, request):
        # Check if the user is an admin
        if request.user.role != 'admin':
            return Response({"error": "Unauthorized. Only admins can access this view."}, status=status.HTTP_403_FORBIDDEN)

        # Fetch technicians who are NOT linked to any request
        technicians = Technetion.objects.filter(assigned_requests__isnull=True)

        # Serialize the data
        serializer = TechnetionSignupSerializer(technicians, many=True)

        return Response(serializer.data, status=status.HTTP_200_OK)




# Admin Assign Technician
class AdminAssignTechnicianView(APIView):
    authentication_classes = [TechnetionTokenAuthentication]
    permission_classes = [IsAuthenticated]

    def post(self, request, request_id):
        # Check if the user is an admin
        if request.user.role != "admin":
            return Response({"error": "Unauthorized"}, status=status.HTTP_403_FORBIDDEN)

        # Get technician_id from the request body
        technician_id = request.data.get('technician_id')
        if not technician_id:
            return Response({"error": "technician_id is required in the request body"}, status=status.HTTP_400_BAD_REQUEST)

        try:
            # Fetch the request and technician
            job_request = Requests.objects.get(id=request_id)
            technician = Technetion.objects.get(id=technician_id)

            # Check if the request is already completed
            if job_request.is_done:
                return Response({"error": "Cannot assign a completed job"}, status=status.HTTP_400_BAD_REQUEST)

            # Assign the technician to the request
            job_request.technician.add(technician)
            job_request.save()

            return Response({"message": "Technician assigned successfully"}, status=status.HTTP_200_OK)
        except Requests.DoesNotExist:
            return Response({"error": "Request not found"}, status=status.HTTP_404_NOT_FOUND)
        except Technetion.DoesNotExist:
            return Response({"error": "Technician not found"}, status=status.HTTP_404_NOT_FOUND)






class TechnicianAssignedRequestsView(APIView):
    authentication_classes = [TechnetionTokenAuthentication]  # Use custom authentication
    permission_classes = [IsAuthenticated]  # Ensure the user is authenticated

    def get(self, request):
        # Ensure the user is a technician
        if request.user.role != 'technician':
            return Response({"error": "Unauthorized. Only technicians can access this view."}, status=status.HTTP_403_FORBIDDEN)

        # Fetch all requests assigned to the logged-in technician
        assigned_requests = Requests.objects.filter(technician=request.user)
        
        # Serialize the data
        serializer = RequestsSerializer(assigned_requests, many=True)
        
        return Response(serializer.data, status=status.HTTP_200_OK)


class TechnicianCompleteRequestView(APIView):
    authentication_classes = [TechnetionTokenAuthentication]  # Use custom authentication
    permission_classes = [IsAuthenticated]  # Ensure the user is authenticated

    def post(self, request, request_id):
        # Ensure the user is a technician
        if request.user.role != 'technician':
            return Response({"error": "Unauthorized. Only technicians can access this view."}, status=status.HTTP_403_FORBIDDEN)

        try:
            # Fetch the request
            job_request = Requests.objects.get(id=request_id)

            # Check if the technician is assigned to this request
            if request.user not in job_request.technician.all():
                return Response({"error": "You are not assigned to this request."}, status=status.HTTP_403_FORBIDDEN)

            # Check if the request is already completed
            if job_request.is_done:
                return Response({"error": "This request is already completed."}, status=status.HTTP_400_BAD_REQUEST)

            # Mark the request as completed
            job_request.is_done = True
            job_request.repair_completion_date = timezone.now()
            job_request.save()

            # Create a History entry
            History.objects.create(
                user=job_request.user,  # Will be null for business requests
                business=job_request.business,  # Will be null for user requests
                request=job_request
            )

            return Response({"message": "Request marked as completed successfully."}, status=status.HTTP_200_OK)
        except Requests.DoesNotExist:
            return Response({"error": "Request not found."}, status=status.HTTP_404_NOT_FOUND)


            
class TechnicianHistoryView(APIView):
    authentication_classes = [TechnetionTokenAuthentication]  # Use custom authentication
    permission_classes = [IsAuthenticated]  # Ensure the user is authenticated

    def get(self, request):
        # Ensure the user is a technician
        if request.user.role != 'technician':
            return Response({"error": "Unauthorized. Only technicians can access this view."}, status=status.HTTP_403_FORBIDDEN)

        # Fetch all history entries where the technician is linked
        history_entries = History.objects.filter(technician=request.user)

        # Serialize the data
        serializer = HistorySerializer(history_entries, many=True)

        return Response(serializer.data, status=status.HTTP_200_OK)

class AdminHistoryView(APIView):
    authentication_classes = [TechnetionTokenAuthentication]  # Use custom authentication
    permission_classes = [IsAuthenticated]  # Ensure the user is authenticated

    def get(self, request):
        # Check if the user is an admin
        if request.user.role != 'admin':
            return Response({"error": "Unauthorized. Only admins can access this view."}, status=status.HTTP_403_FORBIDDEN)

        # Fetch all history entries for completed requests
        history_entries = History.objects.filter(request__is_done=True)

        # Serialize the data
        serializer = HistorySerializer(history_entries, many=True)

        return Response(serializer.data, status=status.HTTP_200_OK)

class AdminCreateRequestView(APIView):
    authentication_classes = [TechnetionTokenAuthentication]  # Use custom authentication
    permission_classes = [IsAuthenticated]  # Ensure the user is authenticated

    def post(self, request):
        # Check if the user is an admin
        if request.user.role != 'admin':
            return Response({"error": "Unauthorized. Only admins can access this view."}, status=status.HTTP_403_FORBIDDEN)

        # Pass the request context to the serializer
        serializer = RequestsSerializer(data=request.data, context={'request': request})
        if serializer.is_valid():
            serializer.save()  # No need to pass a user, as it's optional for admins
            return Response({"message": "Request created successfully.", "request_id": serializer.data['id']}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class BusinessSignupView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = BusinessSignupSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({"message": "Business account created successfully."}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class BusinessLoginView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = BusinessLoginSerializer(data=request.data)
        if serializer.is_valid():
            business = serializer.validated_data['business']
            token, created = BusinessToken.objects.get_or_create(
                business=business,
                defaults={'key': secrets.token_hex(20)}  # Generate a random token
            )
            return Response({
                "message": "Login successful",
                "token": token.key,
                "business": {
                    "id": business.id,
                    "business_name": business.business_name,
                    "business_email": business.business_email
                }
            }, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class BusinessLogoutView(APIView):
    authentication_classes = [BusinessTokenAuthentication]  # Use custom authentication
    permission_classes = [IsAuthenticated]  # Ensure the user is authenticated

    def post(self, request):
        # Delete the business's token to log them out
        request.user.auth_token.delete()
        return Response({"message": "Logout successful"}, status=status.HTTP_200_OK)

# Business Make Request
class CreateBusinessRequestView(APIView):
    permission_classes = [IsAuthenticated]  # Ensure the user is authenticated

    def post(self, request):
        # Ensure the request is authenticated
        if not request.user or isinstance(request.user, AnonymousUser):
            return Response({"detail": "Authentication credentials were not provided."}, status=status.HTTP_401_UNAUTHORIZED)

        serializer = RequestsSerializer(data=request.data, context={'request': request})
        if serializer.is_valid():
            # Automatically assign the authenticated business to the request
            created_request = serializer.save(business=request.user)
            return Response({"message": "Request created successfully", "request_id": created_request.id}, status=status.HTTP_201_CREATED)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
