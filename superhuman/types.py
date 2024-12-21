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


class Thread(TypedDict):
    id: str
    messages: List[Email]
    subject: str
    snippet: str
    last_message_timestamp: float
