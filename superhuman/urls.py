from django.urls import include, path
from rest_framework.routers import DefaultRouter

from . import views

router = DefaultRouter()
router.register("tokens", views.GmailTokenViewSet)

urlpatterns = [
    path("auth/gmail/", views.GmailAuthView.as_view(), name="gmail-auth"),
    path("contacts/", views.ContactListView.as_view(), name="contact-list"),
    path("send-email/", views.SendEmailView.as_view(), name="send-email"),
    path("search/", views.SearchEmailView.as_view(), name="email-search"),
    path("markdone/", views.MarkDoneView.as_view(), name="mark-done"),
    path("markundone/", views.MarkUndoneView.as_view(), name="mark-undone"),
    path("read/", views.MarkReadView.as_view(), name="mark-read"),
    path("spam/", views.SpamEmailView.as_view(), name="spam-email"),
    path("folders/", views.FolderListView.as_view(), name="folder-list"),
    path("folder-emails/", views.FolderEmailsView.as_view(), name="folder-emails"),
    path("create-folder/", views.CreateFolderView.as_view(), name="create-folder"),
    path("accounts/", views.AccountsView.as_view(), name="accounts"),
    path("star/", views.StarEmailView.as_view(), name="star-email"),
    path("trash/", views.TrashEmailView.as_view(), name="trash-email"),
    path(
        "modify-labels/", views.ModifyThreadLabelsView.as_view(), name="modify-labels"
    ),
    path("attachment/", views.GetAttachmentView.as_view(), name="get-attachment"),
    path("", include(router.urls)),
]
