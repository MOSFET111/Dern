from django.urls import path
from . import views

urlpatterns = [
    path('user/register/', views.UserSignup.as_view(), name='user-signup'),
    path('user/login/', views.UserLoginView.as_view(), name='user-login'),
    path('user/logout/', views.LogoutView.as_view(), name='logout'),
    
    path('user/create-request/', views.CreateUserRequestView.as_view(), name='create-request'),

    path('technician/register/', views.TechnetionSignupView.as_view(), name='technician-signup'),
    path('technician/login/', views.TechnetionLoginView.as_view(), name='technician-login'),
    path('technician/logout/', views.TechnicianLogoutView.as_view(), name='technician-logout'),

    path('technician/requests/', views.TechnicianAssignedRequestsView.as_view(), name='technician-assigned-requests'),

    path('technician/complete-request/<int:request_id>/', views.TechnicianCompleteRequestView.as_view(), name='technician-complete-request'),
    path('technician/history/', views.TechnicianHistoryView.as_view(), name='technician-history'),
    path('admin/requests/', views.AdminViewRequestsView.as_view(), name='admin-view-requests'),

    path('admin/requests/state/pending/', views.PendingRequestsView.as_view(), name='requests-pending'),
    path('admin/requests/state/on-progress/', views.WorkOnProgressRequestsView.as_view(), name='requests-on-progress'),
    path('admin/history/', views.AdminHistoryView.as_view(), name='admin-history'),

    path('admin/technicians/', views.AdminViewTechniciansView.as_view(), name='admin-view-technicians'),
    path('admin/technicians/linked/', views.TechniciansLinkedToRequestView.as_view(), name='technicians-linked'),
    path('admin/technicians/not-linked/', views.TechniciansNotLinkedToRequestView.as_view(), name='technicians-not-linked'),

    path('admin/assign/<int:request_id>/', views.AdminAssignTechnicianView.as_view(), name='admin-assign-technician'),

    path('admin/create-request/', views.AdminCreateRequestView.as_view(), name='admin-create-request'),
    path('business/register/', views.BusinessSignupView.as_view(), name='business-signup'),
    path('business/login/', views.BusinessLoginView.as_view(), name='business-login'),
    path('business/logout/', views.BusinessLogoutView.as_view(), name='business-logout'),

    path('business/create-request/', views.CreateBusinessRequestView.as_view(), name='business-create-request'),
]