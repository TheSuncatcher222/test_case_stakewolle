"""
Модуль с ORM моделями базы данных приложения "user".
"""

from datetime import datetime, timedelta
from typing import Optional

from sqlalchemy import DateTime, Column, ForeignKey, Integer, String, Table, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.sql import func

from src.config import Base, TABLE_REFERRAL_CODE, TABLE_USER

ADDRESS_LEN: int = 256

ORGANIZATION_INN_LEN: int = 12
ORGANIZATION_NAME_LEN: int = 64

REFERRAL_CODE_LEN: int = 25

# INFO: в pydantic.EmailStr разрешенные длины строк составляют 64@63.63
USER_EMAIL_LEN: int = 64 + 63 + 63
USER_HASH_PASS_LEN: int = 256
USER_PHONE_LEN: int = 20
USER_TELEGRAM_LEN: int = 32
USER_USERNAME_LEN: int = 25

REFERRAL_CODE_LIFETIME: timedelta = timedelta(days=7)


class ReferralCode(Base):
    """Декларативная модель представления реферального кода."""

    __tablename__ = TABLE_REFERRAL_CODE
    __tableargs__ = {
        'comment': 'Реферальные коды'
    }

    exp_date: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        comment='дата и время регистрации',
        server_default=func.now() + REFERRAL_CODE_LIFETIME,
    )
    id: Mapped[int] = mapped_column(
        comment='ID',
        primary_key=True,
    )
    code: Mapped[str] = mapped_column(
        String(length=USER_EMAIL_LEN),
        comment='реферальный код',
        unique=True,
    )
    reg_date: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        comment='дата и время регистрации',
        server_default=func.now(),
    )
    user: Mapped['User'] = relationship(
        back_populates='referral_code',
    )
    user_id: Mapped[int] = mapped_column(
        ForeignKey(f'{TABLE_USER}.id'),
        comment='id пользователя',
        unique=True,
    )


user_referral_association = Table(
    'user_referral_association',
    Base.metadata,
    Column('referrer_id', Integer, ForeignKey(f'{TABLE_USER}.id')),
    Column('referral_id', Integer, ForeignKey(f'{TABLE_USER}.id')),
    UniqueConstraint(
        'referrer_id',
        'referral_id',
        name='unique_referrer_referral',
    )
)


class User(Base):
    """Декларативная модель представления пользователя."""

    __tablename__ = TABLE_USER
    __tableargs__ = {
        'comment': 'Пользователи'
    }

    # TODO: нужно подтверждение.
    email: Mapped[str] = mapped_column(
        String(length=USER_EMAIL_LEN),
        comment='email',
        unique=True,
    )
    id: Mapped[int] = mapped_column(
        comment='ID',
        primary_key=True,
    )
    is_active: Mapped[bool] = mapped_column(
        comment='статус активного',
        default=True,
    )
    is_admin: Mapped[bool] = mapped_column(
        comment='статус администратора',
        default=False,
    )
    hashed_password: Mapped[Optional[str]] = mapped_column(
        String(length=USER_HASH_PASS_LEN),
        comment='хэш пароля',
    )
    name_first: Mapped[str] = mapped_column(
        String(length=USER_USERNAME_LEN),
        comment='имя',
    )
    name_last: Mapped[str] = mapped_column(
        String(length=USER_USERNAME_LEN),
        comment='фамилия',
    )
    referrals = relationship(
        'User',
        secondary=user_referral_association,
        primaryjoin=id == user_referral_association.c.referrer_id,
        secondaryjoin=id == user_referral_association.c.referral_id,
        backref='referenced_by',
    )
    referral_code: Mapped['ReferralCode'] = relationship(
        back_populates='user',
    )
    reg_date: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        comment='дата и время регистрации',
        server_default=func.now(),
    )

    def __str__(self) -> str:
        return self.email
