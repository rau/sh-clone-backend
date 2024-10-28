from utils import pretty_print_json
from rest_framework.views import APIView
from rest_framework.response import Response
from google_auth_oauthlib.flow import Flow
from django.conf import settings
from django.shortcuts import redirect
from .models import GmailToken
from rest_framework import viewsets
from rest_framework.permissions import AllowAny
from .models import GmailToken
from rest_framework import serializers
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build


class EmailListView(APIView):
    permission_classes = [AllowAny]

    def get(self, request):
        token = GmailToken.objects.first()
        if not token:
            return Response({"error": "No token found"}, status=404)

        creds = Credentials(
            token=token.token,
            refresh_token=token.refresh_token,
            token_uri="https://oauth2.googleapis.com/token",
            client_id="your_client_id",
            client_secret="your_client_secret",
        )

        service = build("gmail", "v1", credentials=creds)
        results = service.users().messages().list(userId="me", maxResults=10).execute()
        messages = results.get("messages", [])

        emails = []
        for message in messages:
            msg = (
                service.users().messages().get(userId="me", id=message["id"]).execute()
            )
            payload = msg["payload"]
            headers = payload["headers"]

            pretty_print_json(payload)
            pretty_print_json(headers)

            emails.append(
                {
                    "id": msg["id"],
                    "subject": next(
                        h["value"] for h in headers if h["name"] == "Subject"
                    ),
                    "sender": next(h["value"] for h in headers if h["name"] == "From"),
                    "date": next(h["value"] for h in headers if h["name"] == "Date"),
                    "snippet": msg["snippet"],
                    # "body": msg["body"],
                    "read": "UNREAD" in msg["labelIds"],
                }
            )

        return Response(emails)


class GmailAuthView(APIView):
    permission_classes = []

    def get(self, request):
        if "code" in request.GET:
            flow = Flow.from_client_secrets_file(
                "client_secrets.json",
                scopes=["https://www.googleapis.com/auth/gmail.readonly"],
                redirect_uri="http://localhost:8000/api/auth/gmail/",
            )
            flow.fetch_token(code=request.GET.get("code"))
            credentials = flow.credentials

            GmailToken.objects.all().delete()
            GmailToken.objects.create(
                token=credentials.token, refresh_token=credentials.refresh_token
            )
            return redirect("http://localhost:1212/success")

        token = GmailToken.objects.first()
        if token:
            return Response(
                {"token": token.token, "refresh_token": token.refresh_token}
            )

        flow = Flow.from_client_secrets_file(
            "client_secrets.json",
            scopes=["https://www.googleapis.com/auth/gmail.readonly"],
            redirect_uri="http://localhost:8000/api/auth/gmail/",
        )
        auth_url = flow.authorization_url()[0]
        return Response({"auth_url": auth_url})


class GmailTokenSerializer(serializers.ModelSerializer):
    class Meta:
        model = GmailToken
        fields = ["token", "refresh_token", "created_at", "updated_at"]


class GmailTokenViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = GmailToken.objects.all()
    serializer_class = GmailTokenSerializer
    permission_classes = [AllowAny]
