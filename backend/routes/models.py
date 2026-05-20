from pydantic import BaseModel, field_validator
from typing import Optional

class ScanRequest(BaseModel):
    url: str

    @field_validator("url")
    @classmethod
    def url_must_not_be_empty(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("URL cannot be empty")
        return v.strip()

class ScanResponse(BaseModel):
    url: str
    timestamp: str
    status: str
    nivel1: Optional[dict] = None
    nivel2: Optional[dict] = None
    nivel3: Optional[dict] = None
    resumen_general: Optional[dict] = None
