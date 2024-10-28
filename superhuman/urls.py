from django.urls import path, include
from rest_framework.routers import DefaultRouter
from . import views

router = DefaultRouter()
router.register("tokens", views.GmailTokenViewSet)

urlpatterns = [
    path("auth/gmail/", views.GmailAuthView.as_view(), name="gmail-auth"),
    path("emails/", views.EmailListView.as_view(), name="email-list"),
    path("", include(router.urls)),
]
