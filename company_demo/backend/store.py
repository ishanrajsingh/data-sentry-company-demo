from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
from threading import RLock
from typing import Any


class MemoryStore:
    """Seeded local store used when MongoDB Atlas is not configured."""

    backend_name = "seeded-memory"

    def __init__(self) -> None:
        self.users: dict[str, dict[str, Any]] = {}
        self.documents: dict[str, dict[str, Any]] = {}
        self.events: dict[str, dict[str, Any]] = {}
        self.feedback: list[dict[str, Any]] = []
        self.lock = RLock()

    def initialize(self, users: list[dict[str, Any]], documents: list[dict[str, Any]]) -> None:
        with self.lock:
            for user in users:
                self.users.setdefault(user["email"], deepcopy(user))
            for document in documents:
                self.documents.setdefault(document["document_id"], deepcopy(document))

    def find_user(self, email: str) -> dict[str, Any] | None:
        with self.lock:
            user = self.users.get(email.lower())
            return deepcopy(user) if user else None

    def list_documents(self) -> list[dict[str, Any]]:
        with self.lock:
            return deepcopy(list(self.documents.values()))

    def get_document(self, document_id: str) -> dict[str, Any] | None:
        with self.lock:
            document = self.documents.get(document_id)
            return deepcopy(document) if document else None

    def insert_event(self, event: dict[str, Any]) -> None:
        with self.lock:
            self.events[event["event_id"]] = deepcopy(event)

    def get_event(self, event_id: str) -> dict[str, Any] | None:
        with self.lock:
            event = self.events.get(event_id)
            return deepcopy(event) if event else None

    def list_events(self, user_id: str | None, limit: int = 100) -> list[dict[str, Any]]:
        with self.lock:
            events = list(self.events.values())
            if user_id:
                events = [event for event in events if event.get("user_id") == user_id]
            events.sort(key=lambda event: event.get("created_at", ""), reverse=True)
            return deepcopy(events[:limit])

    def add_feedback(self, feedback: dict[str, Any]) -> bool:
        with self.lock:
            if any(item["event_id"] == feedback["event_id"] for item in self.feedback):
                return False
            self.feedback.append(deepcopy(feedback))
            event = self.events.get(feedback["event_id"])
            if event:
                event["feedback"] = {
                    "decision_correct": feedback["decision_correct"],
                    "created_at": feedback["created_at"],
                }
            return True

    def feedback_for_profile(self, role: str, profile_key: str) -> list[dict[str, Any]]:
        with self.lock:
            return deepcopy([
                item for item in self.feedback
                if item.get("role") == role and item.get("profile_key") == profile_key
            ])

    def close(self) -> None:
        return None


class MongoStore:
    backend_name = "mongodb-atlas"

    def __init__(self, uri: str, database_name: str) -> None:
        from pymongo import MongoClient

        self.client = MongoClient(uri, serverSelectionTimeoutMS=7000)
        self.client.admin.command("ping")
        self.database = self.client[database_name]
        self.users = self.database["users"]
        self.documents = self.database["documents"]
        self.events = self.database["audit_events"]
        self.feedback = self.database["feedback"]
        self.users.create_index("email", unique=True)
        self.documents.create_index("document_id", unique=True)
        self.events.create_index([("user_id", 1), ("created_at", -1)])
        self.feedback.create_index("event_id", unique=True)
        self.feedback.create_index([("role", 1), ("profile_key", 1)])

    def initialize(self, users: list[dict[str, Any]], documents: list[dict[str, Any]]) -> None:
        for user in users:
            self.users.update_one({"email": user["email"]}, {"$setOnInsert": user}, upsert=True)
        for document in documents:
            self.documents.update_one(
                {"document_id": document["document_id"]},
                {"$setOnInsert": document},
                upsert=True,
            )

    def find_user(self, email: str) -> dict[str, Any] | None:
        return self.users.find_one({"email": email.lower()}, {"_id": 0})

    def list_documents(self) -> list[dict[str, Any]]:
        return list(self.documents.find({}, {"_id": 0}))

    def get_document(self, document_id: str) -> dict[str, Any] | None:
        return self.documents.find_one({"document_id": document_id}, {"_id": 0})

    def insert_event(self, event: dict[str, Any]) -> None:
        self.events.insert_one(deepcopy(event))

    def get_event(self, event_id: str) -> dict[str, Any] | None:
        return self.events.find_one({"event_id": event_id}, {"_id": 0})

    def list_events(self, user_id: str | None, limit: int = 100) -> list[dict[str, Any]]:
        query = {"user_id": user_id} if user_id else {}
        return list(self.events.find(query, {"_id": 0}).sort("created_at", -1).limit(limit))

    def add_feedback(self, feedback: dict[str, Any]) -> bool:
        from pymongo.errors import DuplicateKeyError

        try:
            self.feedback.insert_one(deepcopy(feedback))
        except DuplicateKeyError:
            return False
        self.events.update_one(
            {"event_id": feedback["event_id"]},
            {"$set": {
                "feedback": {
                    "decision_correct": feedback["decision_correct"],
                    "created_at": feedback["created_at"],
                }
            }},
        )
        return True

    def feedback_for_profile(self, role: str, profile_key: str) -> list[dict[str, Any]]:
        return list(self.feedback.find(
            {"role": role, "profile_key": profile_key},
            {"_id": 0},
        ))

    def close(self) -> None:
        self.client.close()


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()
