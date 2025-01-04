import asyncio
import base64
import json
import re
from email.utils import parsedate_to_datetime
from typing import List

import aiohttp
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build

from .types import Contact, Email, Recipients


def pretty_print_json(json_data):
    print(json.dumps(json_data, indent=4))


def get_credentials(token):
    with open("client_secrets.json", "r") as f:
        client_config = json.load(f)

    client_id = client_config["installed"]["client_id"]
    client_secret = client_config["installed"]["client_secret"]

    return Credentials(
        token=token.token,
        refresh_token=token.refresh_token,
        token_uri="https://oauth2.googleapis.com/token",
        client_id=client_id,
        client_secret=client_secret,
    )


async def fetch_attachment(session, service, msg_id, attachment_id):
    try:
        attachment = await asyncio.get_event_loop().run_in_executor(
            None,
            lambda: service.users()
            .messages()
            .attachments()
            .get(userId="me", messageId=msg_id, id=attachment_id)
            .execute(),
        )
        return attachment["data"]
    except Exception as e:
        print(f"Failed to fetch attachment {attachment_id}: {e}")
        return None


async def fetch_all_attachments(service, msg_id, inline_images):
    async with aiohttp.ClientSession() as session:
        tasks = []
        for cid, img in inline_images.items():
            if "attachmentId" in img:
                task = fetch_attachment(session, service, msg_id, img["attachmentId"])
                tasks.append((cid, task))

        results = {}
        for cid, task in tasks:
            data = await task
            if data:
                data = data.replace("_", "/").replace("-", "+")
                data = re.sub(r"[\n\r]", "", data)
                results[cid] = {
                    "data": data,
                    "mimeType": inline_images[cid]["mimeType"],
                }
        return results


def parse_contact(header: str) -> Contact:
    if "<" in header and ">" in header:
        name = header.split("<")[0].strip().replace('"', "")
        email = header.split("<")[1].strip(">").strip().replace('"', "")
    else:
        name = ""
        email = header.strip().replace('"', "")
    return Contact(name=name, email=email, is_me=False)


def parse_recipients(headers: List[dict]) -> Recipients:
    to_header = next((h["value"] for h in headers if h["name"] == "To"), "")
    cc_header = next((h["value"] for h in headers if h["name"] == "Cc"), "")
    bcc_header = next((h["value"] for h in headers if h["name"] == "Bcc"), "")

    return Recipients(
        to=[
            parse_contact(addr.strip()) for addr in to_header.split(",") if addr.strip()
        ],
        cc=[
            parse_contact(addr.strip()) for addr in cc_header.split(",") if addr.strip()
        ],
        bcc=[
            parse_contact(addr.strip())
            for addr in bcc_header.split(",")
            if addr.strip()
        ],
    )


def process_message(msg: dict, creds: Credentials) -> dict:
    headers = msg["payload"]["headers"]
    subject = next(
        (h["value"] for h in headers if h["name"] == "Subject"), "No Subject"
    )
    from_header = next((h["value"] for h in headers if h["name"] == "From"), "Unknown")
    date = next((h["value"] for h in headers if h["name"] == "Date"), "")
    parsed_date = parsedate_to_datetime(date)

    body = ""
    attachments = []
    inline_images = {}

    def process_part(part):
        nonlocal body

        if "parts" in part:
            for subpart in part["parts"]:
                process_part(subpart)
            return

        mime_type = part.get("mimeType", "")
        headers = part.get("headers", [])

        content_id = next(
            (
                h["value"].strip("<>")
                for h in headers
                if h["name"].lower() == "content-id"
            ),
            None,
        )
        content_disposition = next(
            (h["value"] for h in headers if h["name"].lower() == "content-disposition"),
            "",
        )

        if content_id:
            if "body" in part and "data" in part["body"]:
                inline_images[content_id] = {
                    "data": part["body"]["data"],
                    "mimeType": mime_type,
                }
            elif "body" in part and "attachmentId" in part["body"]:
                inline_images[content_id] = {
                    "attachmentId": part["body"]["attachmentId"],
                    "mimeType": mime_type,
                }

        if "attachment" in content_disposition and not content_id:
            if "body" in part and "attachmentId" in part["body"]:
                attachments.append(
                    {
                        "id": part["body"]["attachmentId"],
                        "filename": part.get("filename", ""),
                        "mimeType": mime_type,
                        "size": part["body"].get("size", 0),
                    }
                )
        elif mime_type == "text/html" and "body" in part and "data" in part["body"]:
            body = base64.urlsafe_b64decode(part["body"]["data"]).decode()

    if "payload" in msg:
        process_part(msg["payload"])

    if body and inline_images:
        service = build("gmail", "v1", credentials=creds)
        attachment_data = asyncio.run(
            fetch_all_attachments(service, msg["id"], inline_images)
        )
        inline_images.update(attachment_data)

        for cid, img in inline_images.items():
            if "data" in img:
                new_src = f'src="data:{img["mimeType"]};base64,{img["data"]}"'
                old_srcs = [
                    f'src="cid:{cid}"',
                    f'src="cid:{cid}@"',
                    f'src="cid:{cid}@[^"]*"',
                ]
                for old_src in old_srcs:
                    body = re.sub(old_src, new_src, body, flags=re.IGNORECASE)

    sender = parse_contact(from_header)
    sender.is_me = "SENT" in msg["labelIds"]

    recipients = parse_recipients(headers)

    return {
        "id": msg["id"],
        "thread_id": msg["threadId"],
        "subject": subject,
        "sender": {"name": sender.name, "email": sender.email, "is_me": sender.is_me},
        "to": {
            "to": [
                {"name": c.name, "email": c.email, "is_me": c.is_me}
                for c in recipients.to
            ],
            "cc": [
                {"name": c.name, "email": c.email, "is_me": c.is_me}
                for c in recipients.cc
            ],
            "bcc": [
                {"name": c.name, "email": c.email, "is_me": c.is_me}
                for c in recipients.bcc
            ],
        },
        "date": parsed_date.isoformat(),
        "timestamp": parsed_date.timestamp(),
        "snippet": msg.get("snippet", ""),
        "read": "UNREAD" not in msg["labelIds"],
        "body": body,
        "attachments": attachments,
    }


async def process_messages_async(
    messages: List[dict], creds: Credentials
) -> List[dict]:
    async def process_single_message(msg):
        return await asyncio.to_thread(process_message, msg, creds)

    tasks = [process_single_message(msg) for msg in messages]
    return await asyncio.gather(*tasks)
