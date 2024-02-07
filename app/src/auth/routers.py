"""
Модуль с эндпоинтами приложения "auth".
"""
from datetime import datetime, timezone

from aiohttp import ClientSession
from fastapi import APIRouter, Depends, status
from fastapi.responses import JSONResponse, Response
from sqlalchemy.engine.result import ChunkedIteratorResult
from sqlalchemy.sql import insert, select, update
from sqlalchemy.sql.dml import Insert, Update
from sqlalchemy.sql.selectable import Select

from src.auth.models import UsedPassResetToken
from src.auth.schemas import (
    AuthLogin, AuthPasswordChange, AuthPasswordReset, AuthPasswordResetConfirm,
    AuthRegister, JwtTokenAccess, JwtTokenRefresh,
    UserRegisterRepresent,
)
from src.auth.tasks import send_password_has_changed_to_mail, send_password_restore_to_mail
from src.auth.utils import (
    dangerous_token_generate, dangerous_token_verify,
    get_current_user_id, hash_password,
    jwt_decode, jwt_generate_pair,
)
from src.celery_app import PRIOR_LOW, PRIOR_IMPORTANT
from src.config import (
    DOMAIN_NAME,
    HUNTER_API_KEY,
    JSON_ERR_ACCOUNT_BLOCKED,
    JSON_ERR_EMAIL_IS_ALREADY_REGISTERED, JSON_ERR_EMAIL_OR_PASS_INVALID,
    JSON_ERR_CREDENTIALS_TYPE, JSON_ERR_PASS_INVALID, JSON_ERR_REFERRAL_CODE_INVALID,
    JWT_TYPE_REFRESH,
)
from src.database import AsyncSession, get_async_session
from src.user.models import ReferralCode, User, user_referral_association

router_auth: APIRouter = APIRouter(
    prefix='/auth',
    tags=['Auth'],
)


@router_auth.post(
    path='/login',
    response_model=JwtTokenAccess,
)
async def auth_login(
    user_data: AuthLogin,
    session: AsyncSession = Depends(get_async_session),
):
    """Осуществляет авторизацию пользователя на сайте."""
    user_data: dict[str, any] = user_data.model_dump()

    email: str = user_data.get('email')
    query: Select = select(User).where(User.email == email)
    queryset: ChunkedIteratorResult = await session.execute(query)
    user: User | None = queryset.scalars().first()

    raw_password: str = user_data.get('password')

    if (
        user is None or
        hash_password(raw_password=raw_password) != user.hashed_password
    ):
        return JSONResponse(
            content=JSON_ERR_EMAIL_OR_PASS_INVALID,
            status_code=status.HTTP_400_BAD_REQUEST,
        )

    if not user.is_active:
        return JSONResponse(
            content=JSON_ERR_ACCOUNT_BLOCKED,
            status_code=status.HTTP_403_FORBIDDEN,
        )

    token_access, _, token_refresh, expires = jwt_generate_pair(
        user_id=user.id,
        is_admin=user.is_admin,
    )

    response = JSONResponse(
        content=JwtTokenAccess(access=token_access).model_dump(),
        status_code=status.HTTP_200_OK,
    )

    response.set_cookie(
        key='refresh',
        value=token_refresh,
        expires=expires,
        httponly=True,
        domain=DOMAIN_NAME,
        secure='true',
    )

    return response


@router_auth.post(
    path='/password-change',
)
async def auth_password_change(
    passwords: AuthPasswordChange,
    user_data: dict[str, any] = Depends(get_current_user_id),
    session: AsyncSession = Depends(get_async_session),
):
    """Изменяет старый пароль на новый."""
    passwords: dict[str, str] = passwords.model_dump()

    if 'err_response' in user_data:
        return user_data.get('err_response')

    query: Select = select(User).where(User.id == user_data.get('id'))
    queryset: ChunkedIteratorResult = await session.execute(query)
    user: User = queryset.scalars().first()

    if hash_password(raw_password=passwords.get('password')) != user.hashed_password:
        return JSONResponse(
            content=JSON_ERR_PASS_INVALID,
            status_code=status.HTTP_400_BAD_REQUEST,
        )

    stmt: Update = update(
        User,
    ).where(
        User.id == user_data.get('id'),
    ).values(
        hashed_password=hash_password(raw_password=passwords.get('new_password'))
    )
    await session.execute(stmt)
    await session.commit()

    username: str = f'{user.name_first} {user.name_last}'
    send_password_has_changed_to_mail.apply_async(
        args=(username,),
        property=PRIOR_IMPORTANT,
    )

    return JSONResponse(
        content={
            'password_change': 'Пароль успешно изменен'
        },
        status_code=status.HTTP_200_OK,
    )


@router_auth.post(
    path='/password-reset',
)
async def password_reset(
    email: AuthPasswordReset,
    session: AsyncSession = Depends(get_async_session),
):
    """
    Осуществляет первый этап восстановления пароля:
    отправляет ссылку для восстановления пароля.
    """
    email: dict[str, str] = email.model_dump()
    query: Select = select(User).where(User.email == email.get('email'))
    queryset: ChunkedIteratorResult = await session.execute(query)
    user: User | None = queryset.scalars().first()

    if user:
        reset_token: str = dangerous_token_generate({'id': user.id})
        url_pass_reset_confirm: str = (
            f'https://{DOMAIN_NAME}/api/auth/password-reset-confirm/{reset_token}'
        )
        send_password_restore_to_mail.apply_async(
            args=(url_pass_reset_confirm,),
            property=PRIOR_LOW,
        )
    return Response(status_code=status.HTTP_200_OK)


@router_auth.post(
    path='/password-reset-confirm',
)
async def password_reset_confirm(
    passwords: AuthPasswordResetConfirm,
    session: AsyncSession = Depends(get_async_session),
):
    """
    Осуществляет второй этап восстановления пароля:
    устанавливает новый пароль пользователя.
    """
    # TODO: логгировать неуспешные попытки. Сделать задержку.
    headers: dict[str, str] = {'Referrer-Policy': 'no-referrer'}

    passwords: dict[str, str] = passwords.model_dump()
    reset_token: str = passwords.get('reset_token')
    token_data: dict = dangerous_token_verify(token=reset_token)

    user: None = None
    if token_data is not None:
        query: Select = select(UsedPassResetToken).where(UsedPassResetToken.token == reset_token)
        queryset: ChunkedIteratorResult = await session.execute(query)
        token: UsedPassResetToken | None = queryset.scalars().first()
        if token is None:
            query: Select = select(User).where(User.id == token_data.get('id'))
            queryset: ChunkedIteratorResult = await session.execute(query)
            user: User | None = queryset.scalars().first()
    if user is None:
        return JSONResponse(
            content={
                'password_reset': (
                    'Произошла ошибка. Пожалуйста, запросите новую '
                    'ссылку восстановления пароля'
                )
            },
            status_code=status.HTTP_400_BAD_REQUEST,
            headers=headers,
        )

    stmt: Update = update(
        User,
    ).where(
        User.id == token_data.get('id'),
    ).values(
        hashed_password=hash_password(raw_password=passwords.get('new_password'))
    )
    await session.execute(stmt)

    stmt: Insert = insert(
        UsedPassResetToken,
    ).values(
        token=reset_token,
    )
    await session.execute(stmt)
    await session.commit()

    username: str = f'{user.name_first} {user.name_last}'
    send_password_has_changed_to_mail.apply_async(
        args=(username,),
        property=PRIOR_IMPORTANT,
    )

    return JSONResponse(
        content={
            'password_reset': "Пароль учетной записи успешно изменен"
        },
        status_code=status.HTTP_200_OK,
        headers=headers,
    )


@router_auth.post(
    path='/refresh',
    response_model=JwtTokenAccess
)
async def auth_refresh(
    refresh_token: JwtTokenRefresh,
):
    """
    Осуществляет обновление токена доступа
    при предъявлении валидного токена обновления.
    """
    token_data: dict[str, any] = refresh_token.model_dump()
    token_data: dict[str, any] = jwt_decode(jwt_token=token_data['refresh'])
    if token_data.get('err_response', None) is not None:
        return token_data.get('err_response')
    if token_data.get('type') != JWT_TYPE_REFRESH:
        return JSONResponse(
            content=JSON_ERR_CREDENTIALS_TYPE,
            status_code=status.HTTP_401_UNAUTHORIZED,
        )

    access_token, _, _, _ = jwt_generate_pair(
        user_id=token_data.get('sub'),
        is_admin=token_data.get('is_admin', False),
        refresh=True,
    )
    return {'access': access_token}


@router_auth.post(
    path='/register',
    response_model=UserRegisterRepresent,
)
async def auth_register(
    user_data: AuthRegister,
    session: AsyncSession = Depends(get_async_session),
):
    """
    Осуществляет регистрацию пользователя на сайте.

    Осуществляет хеширование пароля.
    """
    user_data: dict[str, str] = user_data.model_dump()

    email: str = user_data.get('email')
    query: Select = select(User).where(User.email == email)
    queryset: ChunkedIteratorResult = await session.execute(query)
    user: User | None = queryset.scalars().first()
    if user is not None:
        return JSONResponse(
            content=JSON_ERR_EMAIL_IS_ALREADY_REGISTERED,
            status_code=status.HTTP_400_BAD_REQUEST,
        )

    _, email_domain = email.split('@')
    user_first_name: str = user_data.get('name_first')
    user_last_name: str = user_data.get('name_last')
    hunter_email_finder_link: str = (
        f'https://api.hunter.io/v2/email-finder?domain={email_domain}'
        f'&first_name={user_first_name}&last_name={user_last_name}'
        f'&api_key={HUNTER_API_KEY}'
    )
    async with ClientSession() as http_session:
        async with http_session.get(hunter_email_finder_link) as response:
            if response.status != 200:
                # INFO: тут нужна бизнес логика. Можно закинуть email в очередь
                #       Celery на повторную попытку анализа. В случае неуспеха
                #       можно отправить в тех.поддержку.
                # raise HTTPException(status_code=response.status, detail="Error accessing data")

                # INFO: или подключить логгер.
                # from src.logger import get_logger, Logger
                # logger: Logger = get_logger(name=__name__)
                # logger.warning(f'Неудачная попытка проверить email {user.email} на hunter!')

                # INFO: или вообще ничего не делать.
                pass
            else:
                # INFO: будет получен вот такой JSON, и можно расширить бизнес логику.
                response_data: dict[str, any] = {  # noqa (F841)
                    "data": {
                        "first_name": "Alexis",
                        "last_name": "Ohanian",
                        "email": "alexis@reddit.com",
                        "score": 97,
                        "domain": "reddit.com",
                        "accept_all": False,
                        "position": "Cofounder",
                        "twitter": None,
                        "linkedin_url": None,
                        "phone_number": None,
                        "company": "Reddit",
                        "sources": [
                            {
                                "domain": "redditblog.com",
                                "uri": "http://redditblog.com/2008/10/22/widgets-get-an-upgrade-and-a-firefox-extension-that-will-rock-your-world",
                                "extracted_on": "2018-10-19",
                                "last_seen_on": "2021-05-18",
                                "still_on_page": True
                            },
                            {},
                        ],
                        "verification": {
                            "date": "2021-06-14",
                            "status": "valid"
                        }
                    },
                    "meta": {
                        "params": {
                            "first_name": "Alexis",
                            "last_name": "Ohanian",
                            "full_name": None,
                            "domain": "reddit.com",
                            "company": None,
                            "max_duration": None
                        }
                    }
                }
                pass

    referral_code: str | None = user_data.pop('from_referral_code', None)
    referrer_user: None = None
    if referral_code is not None:
        query: Select = select(ReferralCode, User).where(ReferralCode.code == referral_code).join(User)
        queryset: ChunkedIteratorResult = await session.execute(query)
        data: tuple[ReferralCode, User] | None = queryset.fetchone()
        if data is not None:
            referral_code, referrer_user = data
        if referrer_user is None or referral_code.exp_date < datetime.utcnow().replace(tzinfo=timezone.utc):
            return JSONResponse(
                content=JSON_ERR_REFERRAL_CODE_INVALID,
                status_code=status.HTTP_400_BAD_REQUEST,
            )

    raw_password: str = user_data.pop('password')
    user_data['hashed_password']: str = hash_password(raw_password=raw_password)

    stmt: Insert = insert(User).values(**user_data).returning(User)
    result = await session.execute(stmt)
    new_user: User = result.fetchone()[0]

    if referrer_user is not None:
        stmt = insert(
            user_referral_association,
        ).values(
            referrer_id=referrer_user.id,
            referral_id=new_user.id,
        )
        await session.execute(stmt)

    await session.commit()

    return new_user
