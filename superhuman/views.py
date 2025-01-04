import asyncio
import base64
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import List

from asgiref.sync import sync_to_async
from django.shortcuts import redirect
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.viewsets import ReadOnlyModelViewSet

from .models import GmailToken
from .serializers import GmailTokenSerializer
from .types import Email, Folder
from .utils import (
    get_credentials,
    parse_recipients,
    process_message,
    process_messages_async,
)


class SendEmailView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        account_id = request.headers.get("X-Account-ID")
        token = GmailToken.objects.get(id=account_id)
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


class GmailAuthView(APIView):
    permission_classes = []

    def get(self, request):
        flow = Flow.from_client_secrets_file(
            "client_secrets.json",
            scopes=[
                "openid",
                "https://www.googleapis.com/auth/gmail.readonly",
                "https://www.googleapis.com/auth/gmail.send",
                "https://www.googleapis.com/auth/gmail.compose",
                "https://www.googleapis.com/auth/gmail.modify",
                # "https://www.googleapis.com/auth/gmail.metadata",
                "https://www.googleapis.com/auth/contacts.readonly",
                "https://www.googleapis.com/auth/userinfo.email",
                "https://www.googleapis.com/auth/userinfo.profile",
                "https://mail.google.com/",
            ],
            redirect_uri="http://localhost:8000/api/auth/gmail/",
        )
        if "code" in request.GET:
            flow.fetch_token(code=request.GET.get("code"))
            credentials = flow.credentials

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

    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        instance.delete()
        return Response(status=204)


class ContactListView(APIView):
    permission_classes = [AllowAny]

    def get(self, request):
        token = GmailToken.objects.get(id=request.headers.get("X-Account-ID"))
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
            # if to_header:
            #     for contact in parse_recipients(to_header):
            #         key = f"{contact['name']}|{contact['email']}"
            #         contact_freq[key] = contact_freq.get(key, 0) + 1

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
        token = GmailToken.objects.get(id=request.headers.get("X-Account-ID"))
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

            emails.append(process_message(msg, creds))

        return Response(emails)


class MarkDoneView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        token = GmailToken.objects.get(id=request.headers.get("X-Account-ID"))
        if not token:
            return Response({"error": "No token found"}, status=404)

        email_ids = request.data.get("email_ids", [])
        if not email_ids:
            return Response({"error": "No email_ids provided"}, status=400)

        creds = get_credentials(token)
        service = build("gmail", "v1", credentials=creds)

        try:
            labels = service.users().labels().list(userId="me").execute()
            done_label = next(
                (l for l in labels["labels"] if l["name"] == "[SHClone] Done"), None
            )

            if not done_label:
                done_label = (
                    service.users()
                    .labels()
                    .create(
                        userId="me",
                        body={
                            "name": "[SHClone] Done",
                            "labelListVisibility": "labelShow",
                        },
                    )
                    .execute()
                )

            for email_id in email_ids:
                service.users().threads().modify(
                    userId="me",
                    id=email_id,
                    body={
                        "removeLabelIds": ["INBOX"],
                        "addLabelIds": [done_label["id"]],
                    },
                ).execute()
            return Response({"status": "success"})
        except Exception as e:
            print(e)
            return Response({"error": str(e)}, status=400)


class MarkReadView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        token = GmailToken.objects.get(id=request.headers.get("X-Account-ID"))
        if not token:
            return Response({"error": "No token found"}, status=404)

        email_ids = request.data.get("email_ids", [])
        if not email_ids:
            return Response({"error": "No email_ids provided"}, status=400)

        read = request.data.get("read", True)

        creds = get_credentials(token)
        service = build("gmail", "v1", credentials=creds)

        try:
            for email_id in email_ids:
                service.users().threads().modify(
                    userId="me",
                    id=email_id,
                    body={
                        "addLabelIds": [] if read else ["UNREAD"],
                        "removeLabelIds": ["UNREAD"] if read else [],
                    },
                ).execute()
            return Response({"status": "success"})
        except Exception as e:
            print(e)
            return Response({"error": str(e)}, status=400)


class FolderListView(APIView):
    permission_classes = [AllowAny]

    def get(self, request) -> Response:
        token = GmailToken.objects.get(id=request.headers.get("X-Account-ID"))
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
        async def fetch_folder_emails():
            token = await sync_to_async(GmailToken.objects.get)(
                id=request.headers.get("X-Account-ID")
            )
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
                threads = await asyncio.to_thread(
                    lambda: service.users()
                    .threads()
                    .list(userId="me", maxResults=20, labelIds=[label_id])
                    .execute()
                )

                thread_list = []
                for thread in threads.get("threads", []):
                    thread_data = await asyncio.to_thread(
                        lambda: service.users()
                        .threads()
                        .get(userId="me", id=thread["id"], format="full")
                        .execute()
                    )

                    messages = await process_messages_async(
                        thread_data["messages"], creds
                    )
                    messages.sort(key=lambda x: x["timestamp"])

                    if messages:
                        thread_list.append(
                            {
                                "id": thread["id"],
                                "messages": messages,
                                "subject": messages[0]["subject"],
                                "snippet": messages[-1]["snippet"],
                                "last_message_timestamp": messages[-1]["timestamp"],
                                "starred": "STARRED"
                                in thread_data["messages"][-1]["labelIds"],
                            }
                        )

                thread_list.sort(
                    key=lambda x: x["last_message_timestamp"], reverse=True
                )
                print("threaad_list len", len(thread_list))
                return Response(thread_list)

            except Exception as e:
                print(e)
                return Response({"error": str(e)}, status=400)

        return asyncio.run(fetch_folder_emails())


class CreateFolderView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        token = GmailToken.objects.get(id=request.headers.get("X-Account-ID"))
        if not token:
            return Response({"error": "No token found"}, status=404)

        folder_name = request.data.get("folder_name")
        if not folder_name:
            return Response({"error": "No folder name provided"}, status=400)

        creds = get_credentials(token)
        service = build("gmail", "v1", credentials=creds)

        try:
            labels = service.users().labels().list(userId="me").execute()
            existing_labels = [label["name"] for label in labels.get("labels", [])]

            if folder_name in existing_labels:
                return Response({"error": "Folder already exists"}, status=400)

            label = (
                service.users()
                .labels()
                .create(
                    userId="me",
                    body={"name": folder_name, "labelListVisibility": "labelShow"},
                )
                .execute()
            )

            return Response(
                {
                    "id": label["id"],
                    "name": label["name"],
                    "type": label["type"],
                    "message_count": 0,
                }
            )

        except Exception as e:
            print(e)
            return Response({"error": str(e)}, status=400)


class AccountsView(APIView):
    permission_classes = [AllowAny]

    def get(self, _):
        tokens = GmailToken.objects.all()
        if not tokens:
            return Response({"error": "No token found"}, status=404)

        accounts = []
        for token in tokens:
            creds = get_credentials(token)
            service = build("oauth2", "v2", credentials=creds)

            try:
                user_info = service.userinfo().get().execute()
                accounts.append(
                    {
                        "id": token.id,
                        "email": user_info.get("email"),
                        "name": user_info.get("name"),
                        "picture": user_info.get("picture"),
                        "provider": "gmail",
                    }
                )
            except Exception as e:
                print(e)
                continue

        return Response(accounts)


class MarkUndoneView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        token = GmailToken.objects.get(id=request.headers.get("X-Account-ID"))
        if not token:
            return Response({"error": "No token found"}, status=404)

        email_ids = request.data.get("email_ids", [])
        if not email_ids:
            return Response({"error": "No email_ids provided"}, status=400)

        creds = get_credentials(token)
        service = build("gmail", "v1", credentials=creds)

        try:
            labels = service.users().labels().list(userId="me").execute()
            done_label = next(
                (l for l in labels["labels"] if l["name"] == "[SHClone] Done"), None
            )

            if done_label:
                for email_id in email_ids:
                    service.users().threads().modify(
                        userId="me",
                        id=email_id,
                        body={
                            "addLabelIds": ["INBOX"],
                            "removeLabelIds": [done_label["id"]],
                        },
                    ).execute()
                return Response({"status": "success"})
            return Response({"error": "Done label not found"}, status=400)
        except Exception as e:
            print(e)
            return Response({"error": str(e)}, status=400)


class StarEmailView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        token = GmailToken.objects.get(id=request.headers.get("X-Account-ID"))
        if not token:
            return Response({"error": "No token found"}, status=404)

        email_ids = request.data.get("email_ids", [])
        if not email_ids:
            return Response({"error": "No email_ids provided"}, status=400)

        star = request.data.get("star", True)

        creds = get_credentials(token)
        service = build("gmail", "v1", credentials=creds)

        try:
            for email_id in email_ids:
                service.users().threads().modify(
                    userId="me",
                    id=email_id,
                    body={
                        "addLabelIds": ["STARRED"] if star else [],
                        "removeLabelIds": ["STARRED"] if not star else [],
                    },
                ).execute()
            return Response({"status": "success"})
        except Exception as e:
            print(e)
            return Response({"error": str(e)}, status=400)


class TrashEmailView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        token = GmailToken.objects.get(id=request.headers.get("X-Account-ID"))
        if not token:
            return Response({"error": "No token found"}, status=404)

        email_ids = request.data.get("email_ids", [])
        if not email_ids:
            return Response({"error": "No email_ids provided"}, status=400)

        creds = get_credentials(token)
        service = build("gmail", "v1", credentials=creds)

        trash = request.data.get("trash", True)

        try:
            for email_id in email_ids:
                service.users().threads().modify(
                    userId="me",
                    id=email_id,
                    body={
                        "addLabelIds": ["TRASH"] if trash else ["INBOX"],
                        "removeLabelIds": ["TRASH"] if not trash else ["INBOX"],
                    },
                ).execute()
            return Response({"status": "success"})
        except Exception as e:
            print(e)
            return Response({"error": str(e)}, status=400)


class SpamEmailView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        token = GmailToken.objects.get(id=request.headers.get("X-Account-ID"))
        if not token:
            return Response({"error": "No token found"}, status=404)

        email_ids = request.data.get("email_ids", [])
        if not email_ids:
            return Response({"error": "No email_ids provided"}, status=400)

        creds = get_credentials(token)
        service = build("gmail", "v1", credentials=creds)

        spam = request.data.get("spam", True)

        try:
            for email_id in email_ids:
                service.users().threads().modify(
                    userId="me",
                    id=email_id,
                    body={
                        "addLabelIds": ["SPAM"] if spam else ["INBOX"],
                        "removeLabelIds": ["SPAM"] if not spam else ["INBOX"],
                    },
                ).execute()
            return Response({"status": "success"})
        except Exception as e:
            print(e)
            return Response({"error": str(e)}, status=400)


class ModifyThreadLabelsView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        token = GmailToken.objects.get(id=request.headers.get("X-Account-ID"))
        if not token:
            return Response({"error": "No token found"}, status=404)

        thread_ids = request.data.get("thread_ids", [])
        if not thread_ids:
            return Response({"error": "No thread_ids provided"}, status=400)

        add_labels = request.data.get("add_labels", [])
        remove_labels = request.data.get("remove_labels", [])

        creds = get_credentials(token)
        service = build("gmail", "v1", credentials=creds)

        try:
            for thread_id in thread_ids:
                service.users().threads().modify(
                    userId="me",
                    id=thread_id,
                    body={
                        "addLabelIds": add_labels,
                        "removeLabelIds": remove_labels,
                    },
                ).execute()
            return Response({"status": "success"})
        except Exception as e:
            print(e)
            return Response({"error": str(e)}, status=400)


class GetAttachmentView(APIView):
    permission_classes = [AllowAny]

    def get(self, request):
        token = GmailToken.objects.get(id=request.headers.get("X-Account-ID"))
        if not token:
            return Response({"error": "No token found"}, status=404)

        message_id = request.GET.get("message_id")
        attachment_id = request.GET.get("attachment_id")
        if not message_id or not attachment_id:
            return Response(
                {"error": "Missing message_id or attachment_id"}, status=400
            )

        creds = get_credentials(token)
        service = build("gmail", "v1", credentials=creds)

        try:
            attachment = (
                service.users()
                .messages()
                .attachments()
                .get(userId="me", messageId=message_id, id=attachment_id)
                .execute()
            )

            data = attachment["data"]
            return Response({"data": data})
        except Exception as e:
            print(e)
            return Response({"error": str(e)}, status=400)
