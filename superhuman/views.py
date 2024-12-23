import base64
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import List, TypedDict

from django.shortcuts import redirect
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.viewsets import ReadOnlyModelViewSet

from .models import GmailToken
from .serializers import GmailTokenSerializer
from .types import Email, Folder, Thread
from .utils import (
    get_credentials,
    parse_email_headers,
    parse_recipients,
    pretty_print_json,
)


class SendEmailView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        token = GmailToken.objects.first()
        if not token:
            return Response({"error": "No token found"}, status=404)

        creds = get_credentials(token)
        service = build("gmail", "v1", credentials=creds)

        message = MIMEMultipart()
        message["to"] = ",".join(request.data["to"])
        message["subject"] = request.data["subject"]

        print(request.data)

        if request.data.get("cc"):
            message["cc"] = ",".join(request.data["cc"])
        if request.data.get("bcc"):
            message["bcc"] = ",".join(request.data["bcc"])
        if request.data.get("reply_to_email"):
            message["inReplyTo"] = request.data["reply_to_email"]

        print(message)
        message.attach(MIMEText(request.data["body"]))

        if request.data.get("attachments"):
            for attachment in request.data["attachments"]:
                part = MIMEApplication(
                    attachment["content"], _subtype=attachment["type"]
                )
                part.add_header(
                    "Content-Disposition", "attachment", filename=attachment["name"]
                )
                message.attach(part)

        raw = base64.urlsafe_b64encode(message.as_bytes()).decode()

        try:
            sent_message = (
                service.users()
                .messages()
                .send(userId="me", body={"raw": raw})
                .execute()
            )
            return Response({"message_id": sent_message["id"]})
        except Exception as e:
            print(e)
            return Response({"error": str(e)}, status=400)


class EmailListView(APIView):
    permission_classes = [AllowAny]

    def get(self, _):
        token = GmailToken.objects.first()
        if not token:
            return Response({"error": "No token found"}, status=404)

        creds = get_credentials(token)
        service = build("gmail", "v1", credentials=creds)

        threads = (
            service.users()
            .threads()
            .list(userId="me", maxResults=20, labelIds=["INBOX"])
            .execute()
        )

        thread_list: List[Thread] = []

        for thread in threads.get("threads", []):
            thread_data = (
                service.users()
                .threads()
                .get(userId="me", id=thread["id"], format="full")
                .execute()
            )

            messages = []
            for msg in thread_data["messages"]:
                email = parse_email_headers(msg["payload"]["headers"], msg)
                messages.append(email)

            messages.sort(key=lambda x: x["timestamp"])

            if messages:
                thread_list.append(
                    {
                        "id": thread["id"],
                        "messages": messages,
                        "subject": messages[0]["subject"],
                        "snippet": messages[-1]["snippet"],
                        "last_message_timestamp": messages[-1]["timestamp"],
                    }
                )

        thread_list.sort(key=lambda x: x["last_message_timestamp"], reverse=True)
        return Response(thread_list)


class GmailAuthView(APIView):
    permission_classes = []

    def get(self, request):
        flow = Flow.from_client_secrets_file(
            "client_secrets.json",
            scopes=[
                "https://www.googleapis.com/auth/gmail.readonly",
                "https://www.googleapis.com/auth/gmail.send",
                "https://www.googleapis.com/auth/gmail.compose",
                "https://www.googleapis.com/auth/gmail.modify",
                # "https://www.googleapis.com/auth/gmail.metadata",
                "https://www.googleapis.com/auth/contacts.readonly",
                "https://mail.google.com/",
            ],
            redirect_uri="http://localhost:8000/api/auth/gmail/",
            # access_type="offline",
            # prompt="consent",
        )
        if "code" in request.GET:
            flow.fetch_token(code=request.GET.get("code"))
            credentials = flow.credentials

            GmailToken.objects.all().delete()
            GmailToken.objects.create(
                token=credentials.token, refresh_token=credentials.refresh_token
            )
            return redirect("http://localhost:1212/success")

        auth_url = flow.authorization_url(
            access_type="offline", prompt="consent", include_granted_scopes="true"
        )[0]
        return Response({"auth_url": auth_url})


class GmailTokenViewSet(ReadOnlyModelViewSet):
    queryset = GmailToken.objects.all()
    serializer_class = GmailTokenSerializer
    permission_classes = [AllowAny]


class ContactListView(APIView):
    permission_classes = [AllowAny]

    def get(self, _):
        token = GmailToken.objects.first()
        if not token:
            return Response({"error": "No token found"}, status=404)

        creds = get_credentials(token)
        service = build("gmail", "v1", credentials=creds)

        results = (
            service.users()
            .messages()
            .list(userId="me", maxResults=500, q="in:sent")
            .execute()
        )

        contact_freq = {}
        messages = results.get("messages", [])

        for message in messages:
            msg = (
                service.users().messages().get(userId="me", id=message["id"]).execute()
            )
            headers = msg["payload"]["headers"]
            to_header = next((h["value"] for h in headers if h["name"] == "to"), "")
            if to_header:
                for contact in parse_recipients(to_header):
                    key = f"{contact['name']}|{contact['email']}"
                    contact_freq[key] = contact_freq.get(key, 0) + 1

        contacts = [
            {
                "name": k.split("|")[0] or k.split("|")[1],
                "email": k.split("|")[1],
                "frequency": v,
            }
            for k, v in contact_freq.items()
        ]

        contacts.sort(key=lambda x: x["frequency"], reverse=True)

        print(contacts[:100])

        return Response(contacts[:100])


class SearchEmailView(APIView):
    permission_classes = [AllowAny]

    def get(self, request):
        token = GmailToken.objects.first()
        if not token:
            return Response({"error": "No token found"}, status=404)

        query = request.GET.get("q", "")
        from_filter = request.GET.get("from", "")
        to_filter = request.GET.get("to", "")
        subject_filter = request.GET.get("subject", "")
        label_filter = request.GET.get("in", "inbox")

        search_query = []
        if query:
            search_query.append(query)
        if from_filter:
            search_query.append(f"from:{from_filter}")
        if to_filter:
            search_query.append(f"to:{to_filter}")
        if subject_filter:
            search_query.append(f"subject:{subject_filter}")
        if label_filter:
            search_query.append(f"in:{label_filter}")

        creds = get_credentials(token)
        service = build("gmail", "v1", credentials=creds)

        results = (
            service.users()
            .messages()
            .list(userId="me", maxResults=20, q=" ".join(search_query))
            .execute()
        )

        messages = results.get("messages", [])
        emails: List[Email] = []

        for message in messages:
            msg = (
                service.users()
                .messages()
                .get(userId="me", id=message["id"], format="full")
                .execute()
            )
            payload = msg["payload"]
            headers = payload["headers"]

            emails.append(parse_email_headers(headers, msg))

        return Response(emails)


class MarkDoneView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        token = GmailToken.objects.first()
        if not token:
            return Response({"error": "No token found"}, status=404)

        email_id = request.data.get("email_id")
        if not email_id:
            return Response({"error": "No email_id provided"}, status=400)

        creds = get_credentials(token)
        service = build("gmail", "v1", credentials=creds)

        try:
            service.users().messages().modify(
                userId="me",
                id=email_id,
                body={"removeLabelIds": ["INBOX"]},
            ).execute()
            return Response({"status": "success"})
        except Exception as e:
            print(e)
            return Response({"error": str(e)}, status=400)


class MarkReadView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        token = GmailToken.objects.first()
        if not token:
            return Response({"error": "No token found"}, status=404)

        email_id = request.data.get("email_id")
        if not email_id:
            return Response({"error": "No email_id provided"}, status=400)

        creds = get_credentials(token)
        service = build("gmail", "v1", credentials=creds)

        try:
            service.users().messages().modify(
                userId="me", id=email_id, body={"removeLabelIds": ["UNREAD"]}
            ).execute()
            return Response({"status": "success"})
        except Exception as e:
            return Response({"error": str(e)}, status=400)


class FolderListView(APIView):
    permission_classes = [AllowAny]

    def get(self, _) -> Response:
        token = GmailToken.objects.first()
        if not token:
            return Response({"error": "No token found"}, status=404)

        creds = get_credentials(token)
        service = build("gmail", "v1", credentials=creds)

        try:
            labels = service.users().labels().list(userId="me").execute()
            folders: List[Folder] = []

            for label in labels.get("labels", []):
                label_info = (
                    service.users().labels().get(userId="me", id=label["id"]).execute()
                )
                folders.append(
                    {
                        "id": label_info["id"],
                        "name": label_info["name"],
                        "type": label_info["type"],
                        "message_count": label_info.get("messagesTotal", 0),
                    }
                )

            return Response(folders)
        except Exception as e:
            return Response({"error": str(e)}, status=400)


class FolderEmailsView(APIView):
    permission_classes = [AllowAny]

    def get(self, request) -> Response:
        token = GmailToken.objects.first()
        if not token:
            return Response({"error": "No token found"}, status=404)

        folder_id = request.GET.get("folder_id")
        if not folder_id:
            return Response({"error": "No folder_id provided"}, status=400)

        system_labels = {
            "inbox": "INBOX",
            "sent": "SENT",
            "drafs": "DRAFT",
            "spam": "SPAM",
            "trash": "TRASH",
            "important": "IMPORTANT",
            "starred": "STARRED",
            "unread": "UNREAD",
        }

        label_id = system_labels.get(folder_id.lower(), folder_id)

        creds = get_credentials(token)
        service = build("gmail", "v1", credentials=creds)

        try:
            threads = (
                service.users()
                .threads()
                .list(userId="me", maxResults=20, labelIds=[label_id])
                .execute()
            )

            thread_list: List[Thread] = []

            for thread in threads.get("threads", []):
                thread_data = (
                    service.users()
                    .threads()
                    .get(userId="me", id=thread["id"], format="full")
                    .execute()
                )

                messages = []
                for msg in thread_data["messages"]:
                    email = parse_email_headers(msg["payload"]["headers"], msg)
                    messages.append(email)

                messages.sort(key=lambda x: x["timestamp"])

                if messages:
                    thread_list.append(
                        {
                            "id": thread["id"],
                            "messages": messages,
                            "subject": messages[0]["subject"],
                            "snippet": messages[-1]["snippet"],
                            "last_message_timestamp": messages[-1]["timestamp"],
                        }
                    )

            thread_list.sort(key=lambda x: x["last_message_timestamp"], reverse=True)
            return Response(thread_list)
        except Exception as e:
            print(e)
            return Response({"error": str(e)}, status=400)
