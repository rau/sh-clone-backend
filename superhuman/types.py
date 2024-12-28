from typing import List, TypedDict


class Contact(TypedDict):
    name: str
    email: str


class Email(TypedDict):
    id: str
    thread_id: str
    subject: str
    sender: Contact
    to: List[Contact]
    date: str
    timestamp: float
    snippet: str
    read: bool
    body: str


class Thread(TypedDict):
    id: str
    messages: List[Email]
    subject: str
    snippet: str
    last_message_timestamp: float


class Folder(TypedDict):
    id: str
    name: str
    type: str
    message_count: int


class Contact:
    name: str
    email: str
    is_me: bool = False


class Recipients:
    to: List[Contact]
    cc: List[Contact]
    bcc: List[Contact]
