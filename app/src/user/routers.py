"""
Модуль с эндпоинтами приложения "user".
"""

from datetime import datetime

from fastapi import APIRouter, Depends, status
from fastapi_cache.decorator import cache
from pydantic import EmailStr
from sqlalchemy.engine.result import ChunkedIteratorResult
from sqlalchemy.orm import joinedload
from sqlalchemy.sql import delete, insert, select, update
from sqlalchemy.sql.dml import Delete, Insert, Update
from sqlalchemy.sql.selectable import Select

from src.auth.utils import get_current_user_id
from src.database import AsyncSession, get_async_session
from src.user.models import ReferralCode, User, user_referral_association
from src.user.schemas import ReferralCodeRepresent, UserRepresent
from src.user.utils import generate_referral_code

router_users: APIRouter = APIRouter(
    prefix='/users',
    tags=['Users'],
)


@router_users.get(
    path='/me/',
    response_model=UserRepresent | None,
)
async def user_me(
    user_data: dict[str, any] = Depends(get_current_user_id),
    session: AsyncSession = Depends(get_async_session),
):
    """Возвращает данные активного пользователя."""
    if 'err_response' in user_data:
        return user_data['err_response']

    query: Select = select(
        User
    ).where(
        User.id == user_data.get('id')
    ).options(
        joinedload(User.referral_code)
    )
    queryset: ChunkedIteratorResult = await session.execute(query)
    user = queryset.fetchone()[0]

    return user


@router_users.get(
    path='/my-referrals/',
    response_model=list[UserRepresent] | list[None],
)
async def user_my_referrals(
    user_data: dict[str, any] = Depends(get_current_user_id),
    session: AsyncSession = Depends(get_async_session),
):
    """Возвращает данные пользователей-рефералов активного пользователя."""
    if 'err_response' in user_data:
        return user_data['err_response']

    return await _get_referrals(referrer_id=user_data.get('id'), session=session)


@router_users.get(
    path='/{referrer_id}/referrals/',
    response_model=list[UserRepresent] | list[None],
)
async def user_referrals(
    referrer_id: int,
    session: AsyncSession = Depends(get_async_session),
):
    """Возвращает данные пользователей-рефералов пользователя с указанным referrer_id."""
    return await _get_referrals(referrer_id=referrer_id, session=session)


@router_users.post(
    path='/referral-code/create/',
    response_model=ReferralCodeRepresent,
    status_code=status.HTTP_201_CREATED,
)
async def user_referral_code_create(
    user_data: dict[str, any] = Depends(get_current_user_id),
    session: AsyncSession = Depends(get_async_session),
):
    """Создает или обновляет реферальный код активному пользователю."""
    if 'err_response' in user_data:
        return user_data['err_response']

    query: Select = select(User.reg_date).where(User.id == user_data.get('id'))
    queryset: ChunkedIteratorResult = await session.execute(query)
    reg_date: datetime = queryset.fetchone()[0]

    referral_code: str = generate_referral_code(user_register_dt=reg_date)

    query: Select = select(ReferralCode).where(User.id == user_data.get('id'))
    queryset: ChunkedIteratorResult = await session.execute(query)
    queryset: datetime = queryset.fetchone()

    if queryset is None:
        stmt: Insert = insert(
            ReferralCode
        ).values(
            code=referral_code,
            user_id=user_data.get('id')
        ).returning(
            ReferralCode
        )
    else:
        stmt: Update = update(
            ReferralCode
        ).values(
            code=referral_code,
            user_id=user_data.get('id')
        ).returning(
            ReferralCode
        )
    queryset: ChunkedIteratorResult = await session.execute(stmt)
    referral_code: ReferralCode = queryset.fetchone()[0]

    await session.commit()

    return referral_code


@router_users.post(
    path='/referral-code/delete/',
    status_code=status.HTTP_204_NO_CONTENT,
)
async def user_referral_code_delete(
    user_data: dict[str, any] = Depends(get_current_user_id),
    session: AsyncSession = Depends(get_async_session),
):
    """Удаляет реферальный код активному пользователю."""
    if 'err_response' in user_data:
        return user_data['err_response']

    stmt: Delete = delete(ReferralCode).where(ReferralCode.user_id == user_data.get('id'))
    await session.execute(stmt)
    await session.commit()

    return


@router_users.get(
    path='/referral-code/get/{user_email}/',
    response_model=ReferralCodeRepresent | None,
    status_code=status.HTTP_200_OK,
)
@cache(expire=60)
async def user_referral_code_get_by_email(
    user_email: EmailStr,
    session: AsyncSession = Depends(get_async_session),
):
    """
    Выдает реферальный код пользователя реферера.
    Если такого пользователя нет в БД, или он не имеет кода,
    возвращается пустой ответ.
    """
    query: Select = select(
        User
    ).where(
        User.email == user_email.lower()
    ).options(
        joinedload(User.referral_code)
    )
    queryset: ChunkedIteratorResult = await session.execute(query)
    queryset = queryset.fetchone()

    if queryset is not None:
        return queryset[0].referral_code

    return


async def _get_referrals(referrer_id: int, session: AsyncSession) -> list[User | None]:
    """
    Возвращает список пользователей, которые являются
    рефералами для пользователя с id = referrer_id.
    """
    subquery: Select = select(
        user_referral_association.c.referral_id
    ).where(
        user_referral_association.c.referrer_id == referrer_id
    ).scalar_subquery()

    query: Select = select(
        User
    ).where(
        User.id.in_(subquery)
    ).options(
        joinedload(User.referral_code)
    )

    queryset: ChunkedIteratorResult = await session.execute(query)
    users: list[User | None] = [user[0] for user in queryset.fetchall()]

    return users
