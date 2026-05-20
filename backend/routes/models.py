from pydantic import BaseModel
from typing import Optional

class ScanRequest(BaseModel):
    url: str

class ScanResponse(BaseModel):
    url: str
    timestamp: str
    status: str
    nivel1: Optional[dict] = None
    nivel2: Optional[dict] = None
    nivel3: Optional[dict] = None
    resumen_general: Optional[dict] = None
