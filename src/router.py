from pydantic import BaseModel


class Router(BaseModel):
    ip: str | None
    num: int
    time: int
    autonomous_system: str | None
