from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class Message:
    id: int
    direction: str
    protocol: str
    message_type: str
    ngap_fields: dict[str, Any] = field(default_factory=dict)
    nas: dict[str, Any] | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Message":
        return cls(
            id=int(data["id"]),
            direction=data["direction"],
            protocol=data["protocol"],
            message_type=data["message_type"],
            ngap_fields=dict(data.get("ngap_fields", {})),
            nas=dict(data["nas"]) if data.get("nas") is not None else None,
            metadata=dict(data.get("metadata", {})),
        )

    def to_dict(self) -> dict[str, Any]:
        result = {
            "id": self.id,
            "direction": self.direction,
            "protocol": self.protocol,
            "message_type": self.message_type,
        }
        if self.ngap_fields:
            result["ngap_fields"] = self.ngap_fields
        if self.nas is not None:
            result["nas"] = self.nas
        if self.metadata:
            result["metadata"] = self.metadata
        return result


@dataclass
class ProcedureTrace:
    procedure: str
    description: str = ""
    messages: list[Message] = field(default_factory=list)
    mutation_history: list[dict[str, Any]] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ProcedureTrace":
        return cls(
            procedure=data["procedure"],
            description=data.get("description", ""),
            messages=[Message.from_dict(msg) for msg in data.get("messages", [])],
            mutation_history=list(data.get("mutation_history", [])),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "procedure": self.procedure,
            "description": self.description,
            "messages": [msg.to_dict() for msg in self.messages],
            "mutation_history": self.mutation_history,
        }
