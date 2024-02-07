"""
Модуль со схемами валидации данных через Pydantic в приложении "user".
"""

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, EmailStr


class ReferralCodeRepresent(BaseModel):
    """Схема представления значения реферального кода"""
    code: str
    exp_date: datetime


class UserRepresent(BaseModel):
    """Схема представления пользователя."""

    id: int
    name_first: str
    name_last: str
    email: EmailStr
    reg_date: datetime
    referral_code: Optional[ReferralCodeRepresent]
