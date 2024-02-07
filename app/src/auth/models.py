"""
Модуль с ORM моделями базы данных приложения "feedback".
"""

from datetime import datetime, timedelta

from sqlalchemy import DateTime, String
from sqlalchemy.orm import Mapped, mapped_column

from src.config import Base, TABLE_USED_PASS_RESET_TOKEN, ONE_DAY_SEC

TOKEN_MAX_LEN: int = 256


class UsedPassResetToken(Base):
    """
    Декларативная модель представления однажды использованных
    токенов восстановления пароля.
    """

    __tablename__ = TABLE_USED_PASS_RESET_TOKEN
    __tableargs__ = {
        'comment': 'Использованные токены восстановления пароля'
    }

    id: Mapped[int] = mapped_column(
        comment='ID',
        primary_key=True,
    )
    exp_date: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        comment='дата и время окончания срока жизни',
        default=datetime.utcnow() + timedelta(seconds=ONE_DAY_SEC)
    )
    token: Mapped[str] = mapped_column(
        String(length=TOKEN_MAX_LEN),
        comment='токен',
    )
