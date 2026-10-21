from __future__ import annotations

from typing import Annotated, Literal
from uuid import UUID

from pydantic import (
    AwareDatetime,
    BaseModel,
    ConfigDict,
    Field,
    IPvAnyAddress,
    model_validator,
)

Text = Annotated[str, Field(min_length=1, max_length=256)]
Port = Annotated[int, Field(strict=True, ge=1, le=65535)]


class Login(BaseModel):
    model_config = ConfigDict(extra="forbid")
    username: Text
    outcome: Literal["failure", "success"]
    password_length: Annotated[int, Field(strict=True, ge=0, le=65535)]


class Event(BaseModel):
    model_config = ConfigDict(extra="forbid")
    schema_version: Annotated[int, Field(strict=True, ge=1, le=1)]
    event_id: UUID
    occurred_at: AwareDatetime
    received_at: AwareDatetime
    event_type: Literal["login_attempt"]
    cowrie_event_type: Literal["cowrie.login.failed", "cowrie.login.success"]
    sensor_id: Text
    session_id: Text
    source_ip: IPvAnyAddress
    source_port: Port
    protocol: Literal["ssh", "telnet"]
    destination_port: Port
    raw_record_ref: Text
    login: Login

    @model_validator(mode="after")
    def matching_outcome(self) -> Event:
        expected = (
            "success" if self.cowrie_event_type == "cowrie.login.success" else "failure"
        )
        if self.login.outcome != expected:
            raise ValueError("Cowrie type and login outcome disagree")
        return self
