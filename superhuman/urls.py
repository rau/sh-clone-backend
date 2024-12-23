from django.urls import include, path
from rest_framework.routers import DefaultRouter

from . import views

router = DefaultRouter()
router.register("tokens", views.GmailTokenViewSet)

urlpatterns = [
    path("auth/gmail/", views.GmailAuthView.as_view(), name="gmail-auth"),
    path("emails/", views.EmailListView.as_view(), name="email-list"),
    path("contacts/", views.ContactListView.as_view(), name="contact-list"),
    path("send-email/", views.SendEmailView.as_view(), name="send-email"),
    path("search/", views.SearchEmailView.as_view(), name="email-search"),
    path("markdone/", views.MarkDoneView.as_view(), name="mark-done"),
    path("markread/", views.MarkReadView.as_view(), name="mark-read"),
    path("folders/", views.FolderListView.as_view(), name="folder-list"),
    path("folder-emails/", views.FolderEmailsView.as_view(), name="folder-emails"),
    path("", include(router.urls)),
]
