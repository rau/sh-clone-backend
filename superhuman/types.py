from dataclasses import asdict, dataclass
from typing import List, TypedDict


@dataclass
class Contact:
    name: str
    email: str
    is_me: bool

    def to_dict(self):
        return {
            "name": self.name,
            "email": self.email,
            "is_me": self.is_me,
        }


@dataclass
class Recipients:
    to: List[Contact]
    cc: List[Contact]
    bcc: List[Contact]

    def to_dict(self):
        return {
            "to": [c.to_dict() for c in self.to],
            "cc": [c.to_dict() for c in self.cc],
            "bcc": [c.to_dict() for c in self.bcc],
        }


@dataclass
class Attachment:
    filename: str
    mime_type: str
    data: str

    def to_dict(self):
        return {
            "filename": self.filename,
            "mime_type": self.mime_type,
            "data": self.data,
        }


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

    def to_dict(self):
        return {
            "id": self.id,
            "thread_id": self.thread_id,
            "subject": self.subject,
            "sender": self.sender.to_dict(),
            "to": self.to.to_dict(),
            "date": self.date,
            "timestamp": self.timestamp,
            "snippet": self.snippet,
            "read": self.read,
            "body": self.body,
            "attachments": [a.to_dict() for a in self.attachments],
        }


@dataclass
class Thread:
    id: str
    messages: List[Email]
    subject: str
    snippet: str
    last_message_timestamp: float
    starred: bool
    is_draft: bool

    def to_dict(self):
        return {
            "id": self.id,
            "messages": [m.to_dict() for m in self.messages],
            "subject": self.subject,
            "snippet": self.snippet,
            "last_message_timestamp": self.last_message_timestamp,
            "starred": self.starred,
            "is_draft": self.is_draft,
        }


@dataclass
class Folder:
    id: str
    name: str
    type: str
    message_count: int

    def to_dict(self):
        return {
            "id": self.id,
            "name": self.name,
            "type": self.type,
            "message_count": self.message_count,
        }


@dataclass
class Draft(TypedDict):
    id: str
    email: Email
