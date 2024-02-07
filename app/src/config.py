"""
Модуль с настройками сервиса.
"""

import os

from dotenv import load_dotenv
from sqlalchemy.orm import DeclarativeBase

load_dotenv()


"""Настройки базы данных."""


class Base(DeclarativeBase):
    """Инициализирует фабрику создания декларативных классов моделей."""
    pass


DB_HOST: str = os.getenv('DB_HOST')

DB_NAME: str = os.getenv('POSTGRES_DB')

DB_PASS: str = os.getenv('POSTGRES_PASSWORD')

DB_PORT: str = os.getenv('DB_PORT')

DB_USER: str = os.getenv('POSTGRES_USER')

REDIS_DB: str = os.getenv('REDIS_DB')

REDIS_HOST: str = os.getenv('REDIS_HOST')

REDIS_PORT: str = os.getenv('REDIS_PORT')


"""Настройки безопасности."""


DOMAIN_IP: str = os.getenv('DOMAIN_IP')

DOMAIN_NAME: str = os.getenv('DOMAIN_NAME')

HASH_NAME: str = os.getenv('HASH_NAME')

HUNTER_API_KEY: str = os.getenv('HUNTER_API_KEY')

JWT_ALGORITHM: str = os.getenv('JWT_ALGORITHM')

JWT_ACCESS_EXPIRATION_SEC: str = int(os.getenv('JWT_ACCESS_EXPIRATION_SEC'))

JWT_REFRESH_EXPIRATION_SEC: str = int(os.getenv('JWT_REFRESH_EXPIRATION_SEC'))

JWT_TYPE_ACCESS: str = 'access'

JWT_TYPE_REFRESH: str = 'refresh'

ONE_DAY_SEC: int = 60 * 60 * 24

PASS_ENCODE: str = os.getenv('PASS_ENCODE')

SALT: bytes = os.getenv('SALT').encode(PASS_ENCODE)

SECRET_KEY: str = os.getenv('SECRET_KEY')

ITERATIONS: int = int(os.getenv('ITERATIONS'))


"""Настройки моделей ORM в базе данных."""


TABLE_USED_PASS_RESET_TOKEN: str = 'table_used_pass_reset_token'

TABLE_REFERRAL_CODE: str = 'table_referral_code'

TABLE_USER: str = 'table_user'


"""Настройки почтового клиента SMTP."""

DEBUG_EMAIL: bool = bool(os.getenv('DEBUG_EMAIL').lower() == 'true')

SMTP_HOST: str = os.getenv('SMTP_HOST')

SMTP_PASSWORD: str = os.getenv('SMTP_PASSWORD')

SMTP_PORT: str = os.getenv('SMTP_PORT')

SMTP_PROTOCOL: str = os.getenv('SMTP_PROTOCOL')

SMTP_USER: str = os.getenv('SMTP_USER')

SUPPORT_EMAIL_TO: str = os.getenv('SUPPORT_EMAIL_TO')


"""Настройки сервиса."""


ASGI_PORT: int = int(os.getenv('ASGI_PORT'))

DEBUG: str = os.getenv('DEBUG')

if DEBUG == 'True':
    DEBUG: bool = True
    # Параметр "echo" в AsyncEngine, который выводит логи отладки в консоль.
    DEBUG_DB: bool = True
    # Количество работающих worker внутри сервиса.
    WORKERS_AMOUNT: int = 1
else:
    DEBUG: bool = False
    DEBUG_DB: bool = False
    WORKERS_AMOUNT: int = int(os.getenv('WORKERS_AMOUNT'))


def generate_json_error_content(
        detail: str,
        type_resp: str,
        loc: list[str],
        type_err: str
):
    """
    Генерирует content для JSON ответа при возникновении ошибки
    по формату стандартных ошибок FastAPI.
    """
    return {
        'detail': detail,
        'type': type_resp,
        'ctx': {
            'loc': loc,
            'msg': detail,
            'type': type_err,
            'err_code': detail.lower().replace(' ', '_')
        }
    }


JSON_ERR_ACCOUNT_BLOCKED: dict[str, any] = generate_json_error_content(
    detail='Аккаунт временно заблокирован',
    type_resp='validation_error',
    loc=['body', 'email', 'password'],
    type_err='value_error',
)


JSON_ERR_CREDENTIALS_INVALID_EXPIRED: dict[str, any] = generate_json_error_content(
    detail='Токен недействителен или срок его действия истек',
    type_resp='token_not_valid',
    loc=['header', 'Authorization'],
    type_err='value_error'
)

JSON_ERR_CREDENTIALS_TYPE: dict[str, any] = generate_json_error_content(
    detail='Данный токен недействителен',
    type_resp='token_not_valid',
    loc=['header', 'Authorization'],
    type_err='value_error'
)

JSON_ERR_EMAIL_OR_PASS_INVALID: dict[str, any] = generate_json_error_content(
    detail='Адрес электронной почты и(или) пароль недействительны',
    type_resp='validation_error',
    loc=['body', 'email', 'password'],
    type_err='value_error',
)

JSON_ERR_EMAIL_IS_ALREADY_REGISTERED: dict[str, any] = generate_json_error_content(
    detail='Пользователь с таким адресом электронной почты уже зарегистрирован',
    type_resp='validation_error',
    loc=['body', 'email'],
    type_err='value_error',
)

JSON_ERR_PASS_INVALID: dict[str, any] = generate_json_error_content(
    detail='Пароль недействителен',
    type_resp='validation_error',
    loc=['body', 'password'],
    type_err='value_error',
)

JSON_ERR_REFERRAL_CODE_INVALID: dict[str, any] = generate_json_error_content(
    detail='Реферальный код недействителен.',
    type_resp='validation_error',
    loc=['body', 'from_referral_code'],
    type_err='value_error',
)
