from pydantic import BaseModel


class Router(BaseModel):
    """Class for storing router information"""

    ip: str | None
    num: int
    time: int
    autonomous_system: str | None
