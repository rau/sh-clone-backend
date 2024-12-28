import base64
import json
from email.utils import parsedate_to_datetime
from typing import List

from google.oauth2.credentials import Credentials

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


def parse_email_headers(headers: List[dict], msg: dict) -> Email:
    subject = next(
        (h["value"] for h in headers if h["name"] == "Subject"), "No Subject"
    )
    from_header = next((h["value"] for h in headers if h["name"] == "From"), "Unknown")
    date = next((h["value"] for h in headers if h["name"] == "Date"), "")

    parsed_date = parsedate_to_datetime(date)
    body = ""

    if "payload" in msg:
        if "body" in msg["payload"] and "data" in msg["payload"]["body"]:
            body = base64.urlsafe_b64decode(msg["payload"]["body"]["data"]).decode()
        elif "parts" in msg["payload"]:
            for part in msg["payload"]["parts"]:
                if part["mimeType"] == "multipart/alternative":
                    for subpart in part["parts"]:
                        if (
                            subpart["mimeType"] == "text/html"
                            and "data" in subpart["body"]
                        ):
                            body = base64.urlsafe_b64decode(
                                subpart["body"]["data"]
                            ).decode()
                            break
                elif part["mimeType"] == "text/html" and "data" in part["body"]:
                    body = base64.urlsafe_b64decode(part["body"]["data"]).decode()
                    break

    sender = parse_contact(from_header)
    sender["is_me"] = "SENT" in msg["labelIds"]

    return {
        "id": msg["id"],
        "thread_id": msg["threadId"],
        "subject": subject,
        "sender": sender,
        "to": parse_recipients(headers),
        "date": parsed_date.isoformat(),
        "timestamp": parsed_date.timestamp(),
        "snippet": msg.get("snippet", ""),
        "read": "UNREAD" not in msg["labelIds"],
        "body": body,
    }


def parse_contact(header: str) -> Contact:
    if "<" in header and ">" in header:
        name = header.split("<")[0].strip().replace('"', "")
        email = header.split("<")[1].strip(">").strip().replace('"', "")
    else:
        name = ""
        email = header.strip().replace('"', "")
    return {"name": name, "email": email}


def parse_recipients(headers: List[dict]) -> Recipients:
    to_header = next((h["value"] for h in headers if h["name"] == "To"), "")
    cc_header = next((h["value"] for h in headers if h["name"] == "Cc"), "")
    bcc_header = next((h["value"] for h in headers if h["name"] == "Bcc"), "")

    return {
        "to": [
            parse_contact(addr.strip()) for addr in to_header.split(",") if addr.strip()
        ],
        "cc": [
            parse_contact(addr.strip()) for addr in cc_header.split(",") if addr.strip()
        ],
        "bcc": [
            parse_contact(addr.strip())
            for addr in bcc_header.split(",")
            if addr.strip()
        ],
    }
