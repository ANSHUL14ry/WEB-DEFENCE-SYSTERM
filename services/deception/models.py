"""
AEGIS Ω — Synthetic Decoy Application Models
Data structures representing 100% synthetic corporate assets for behavioral observation.
Zero production databases or real credentials are used.
"""

from typing import List, Optional
from pydantic import BaseModel, Field


class DecoyLoginRequest(BaseModel):
    username: str = Field(..., max_length=128)
    password: str = Field(..., max_length=256)
    remember_me: Optional[bool] = False


class DecoyUser(BaseModel):
    id: str
    username: str
    role: str
    department: str
    status: str
    last_login: str


class DecoyProduct(BaseModel):
    id: str
    name: str
    sku: str
    category: str
    price: float
    inventory: int


class DecoyOrder(BaseModel):
    order_id: str
    customer_name: str
    amount: float
    currency: str
    status: str
    items_count: int


class DecoyAdminStats(BaseModel):
    total_users: int
    total_orders: int
    total_revenue_usd: float
    active_sessions: int
    api_requests_today: int
    system_status: str
    platform_version: str
