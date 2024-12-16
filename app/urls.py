from django.urls import path
from .views import *

urlpatterns = [
    path('', api_services_info.as_view()),
    path('auth/', authentication_services.as_view()),
    path('check_post/', check_post_services.as_view()),
    path('woodlogs_counts/', woodlogs_count_check.as_view())
]
