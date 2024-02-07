"""
Модуль с вспомогательными функциями приложения "auth".
"""

from datetime import datetime, timedelta
from hashlib import pbkdf2_hmac
from typing import Annotated

from fastapi import Depends, status
from fastapi.responses import JSONResponse
from fastapi.security import OAuth2PasswordBearer
from itsdangerous import URLSafeTimedSerializer, BadSignature
from jose import jwt
from jose.exceptions import ExpiredSignatureError, JWTClaimsError, JWTError

from src.config import (
    DOMAIN_NAME, HASH_NAME, JWT_ALGORITHM,
    JSON_ERR_CREDENTIALS_INVALID_EXPIRED, JSON_ERR_CREDENTIALS_TYPE,
    JWT_ACCESS_EXPIRATION_SEC, JWT_REFRESH_EXPIRATION_SEC,
    JWT_TYPE_ACCESS, JWT_TYPE_REFRESH,
    ONE_DAY_SEC, PASS_ENCODE, SALT, SECRET_KEY, ITERATIONS,
)

oauth2_scheme: OAuth2PasswordBearer = OAuth2PasswordBearer(tokenUrl='auth/login')


def dangerous_token_generate(data: dict[str, any]) -> str:
    """Генерирует уникальный токен, содержащий данные из параметров функции."""
    serializer: URLSafeTimedSerializer = _get_dangerous_serializer()
    return serializer.dumps(obj=data)


def dangerous_token_verify(token, expiration: int = ONE_DAY_SEC) -> any:
    """
    Верифицирует и возвращает данные из уникального токена.

    Если токен невалидный - возвращает None.
    """
    serializer: URLSafeTimedSerializer = _get_dangerous_serializer()
    try:
        return serializer.loads(token, max_age=expiration)
    except BadSignature:
        return None


def get_current_user_id(token: Annotated[str, Depends(oauth2_scheme)]) -> dict[str, any]:
    """
    Получает данные пользователя из JWT токена доступа.

    Возвращает None в случае ошибки валидации токена.
    """
    payload: dict[str, any] = jwt_decode(jwt_token=str(token))
    if payload.get('err_response', None) is not None:
        return {
            'err_response': payload.get('err_response')
        }
    if payload.get('type') != JWT_TYPE_ACCESS:
        return {
            'err_response': JSONResponse(
                content=JSON_ERR_CREDENTIALS_TYPE,
                status_code=status.HTTP_401_UNAUTHORIZED,
            )
        }

    user_data: dict[str, any] = {
        'id': int(payload.get('sub')),
        'is_admin': payload.get('is_admin', False),
    }
    return user_data


def hash_password(raw_password: str) -> str:
    """Создает хэш пароля для сохранения в базе данных."""
    hashed_password: str = str(
        # TODO: перейти на passlib
        #       https://fastapi.tiangolo.com/tutorial/security/oauth2-jwt/#install-passlib
        pbkdf2_hmac(
            hash_name=HASH_NAME,
            password=raw_password.encode(PASS_ENCODE),
            salt=SALT,
            iterations=ITERATIONS,
        )
    )
    return hashed_password


def jwt_generate_pair(
        user_id: int, is_admin: bool = False, refresh: bool = False
) -> tuple[str, int, str, int]:
    """
    Создает пару JWT токенов доступа и обновления с payload:
        - id: ID пользователя
        - exp: дата окончания срока жизни (Unix Epoch)
        - is_admin: статус администратора (если пользователь им является)

    Возвращает кортеж, содержащий данные в следующем порядке:
        1) JWT access
        2) JWT access expires
        3) JWT refresh
        4) JWT refresh expires

    Если "refresh == True" - создает и возвращает только токен обновления.
    """
    payload: dict[str, dict[str, any]] = {
        'sub': str(user_id)
    }
    if is_admin:
        payload['is_admin']: bool = is_admin
    access_token, exp_access = _jwt_generate(
        payload=payload,
        token_type=JWT_TYPE_ACCESS,
    )
    if not refresh:
        refresh_token, exp_refresh = _jwt_generate(
            payload=payload,
            token_type=JWT_TYPE_REFRESH,
        )
    else:
        refresh_token = None
        exp_refresh = None

    return access_token, exp_access, refresh_token, exp_refresh


# TODO: возможно стоит избавиться от функционала.
def jwt_decode(jwt_token: str) -> dict[str, any]:
    """
    Читает, валидирует информацию JWT токена.

    Возвращает данные из payload.

    Вызывает jose.exceptions:
        - ExpiredSignatureError: если подпись недействительна
        - JWTClaimsError: если истек срок действия
        - JWTError: произошла ошибка чтения
    """
    try:
        jwt_decode: dict[str, any] = jwt.decode(
            token=jwt_token,
            key=SECRET_KEY,
            algorithms=[JWT_ALGORITHM,],
        )
    except (ExpiredSignatureError, JWTClaimsError, JWTError):
        return {
            'err_response': JSONResponse(
                content=JSON_ERR_CREDENTIALS_INVALID_EXPIRED,
                status_code=status.HTTP_401_UNAUTHORIZED,
            )
        }
    return jwt_decode


def _get_dangerous_serializer() -> URLSafeTimedSerializer:
    """Инициализирует сериализатор генерации токенов."""
    return URLSafeTimedSerializer(
        secret_key=SECRET_KEY,
        salt=SALT,
    )


def _jwt_generate(payload: dict[str, any], token_type: str) -> tuple[str, int]:
    """
    Создает JWT токен с указанными параметрами payload и token_type.

    Возвращает токен и время жизни (Unix).
    """
    if token_type == JWT_TYPE_ACCESS:
        exp_time_sec: int = JWT_ACCESS_EXPIRATION_SEC
    elif token_type == JWT_TYPE_REFRESH:
        exp_time_sec: int = JWT_REFRESH_EXPIRATION_SEC
    else:
        token_type: str = 'unknown'
        exp_time_sec: int = 0
    exp_datetime: datetime = datetime.now() + timedelta(seconds=exp_time_sec)
    exp_unix: int = int(exp_datetime.timestamp())
    payload['exp']: int = exp_unix
    payload['iss']: str = DOMAIN_NAME
    payload['type']: str = token_type
    token: str = jwt.encode(
        claims=payload,
        key=SECRET_KEY,
        algorithm=JWT_ALGORITHM,
    )
    return token, exp_unix
