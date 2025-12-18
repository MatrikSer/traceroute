from pydantic import BaseModel, Field


class Router(BaseModel):
    """Class for storing router information"""

    ip: str | None
    num: int = Field(ge=1)
    time: int = Field(ge=0)
