from dataclasses import dataclass
from typing import List, TypedDict


@dataclass
class Contact:
    name: str
    email: str
    is_me: bool


@dataclass
class Recipients:
    to: List[Contact]
    cc: List[Contact]
    bcc: List[Contact]


@dataclass
class Attachment:
    filename: str
    mime_type: str
    data: str


@dataclass
class Email:
    id: str
    thread_id: str
    subject: str
    sender: Contact
    to: Recipients
    date: str
    timestamp: float
    snippet: str
    read: bool
    body: str
    attachments: List[Attachment]


class Thread(TypedDict):
    id: str
    messages: List[Email]
    subject: str
    snippet: str
    last_message_timestamp: float
    starred: bool


class Folder(TypedDict):
    id: str
    name: str
    type: str
    message_count: int
