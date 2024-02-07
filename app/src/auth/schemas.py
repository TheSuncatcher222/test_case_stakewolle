"""
Модуль со схемами валидации данных через Pydantic в приложении "auth".
"""

from datetime import datetime
from re import fullmatch
from typing import Optional

from pydantic import BaseModel, EmailStr, validator

from src.user.models import REFERRAL_CODE_LEN

NL: str = '\n'

ORGANIZATION_INN_REG_EXP: str = r'^\d{12}$'

REFERRAL_CODE_REGEXP: str = r'^[\d\w]{25}$'

USER_NAME_FIRST_ERROR: str = (
    'Укажите правильное имя (например: Иван или Анна-Мария)'
)
USER_NAME_LAST_ERROR: str = (
    'Укажите правильную фамилию (например: Петров или Баронесса-Ивальди фон Бремзен)'
)
USER_NAME_REGEXP: str = r'^[А-ЯЁа-яё\s\-]{1,40}$'
USER_PASS_RAW_LEN_MAX: int = 50
USER_PASS_RAW_LEN_MIN: int = 8
PASS_SPECIAL_CHARS: str = '!_@#$%^&+='

PASS_CHARS_VALIDATORS: dict[str, str] = {
    lambda s: USER_PASS_RAW_LEN_MIN <= len(s) <= USER_PASS_RAW_LEN_MAX: f'{NL}- длина от {USER_PASS_RAW_LEN_MIN} до {USER_PASS_RAW_LEN_MAX} символов',
    lambda s: any(char.isdigit() for char in s): '\n- включает хотя бы одну цифру (0-9)',
    lambda s: any(char.islower() for char in s): '\n- включает хотя бы одну прописную букву (a-z)',
    lambda s: any(char.isupper() for char in s): '\n- включает хотя бы одну заглавную букву (A-Z)',
    lambda s: any(char in PASS_SPECIAL_CHARS for char in s): f'{NL}- включает хотя бы один специальный символ ({PASS_SPECIAL_CHARS})',
}

TELEGRAM_USERNAME_LEN_MIN: int = 5
TELEGRAM_USERNAME_LEN_MAX: int = 32
TELEGRAM_USERNAME_SPECIAL_CHARS: str = '!_@#$%^&+='
TELEGRAM_USERNAME_REG_EXP: str = r'^[a-zA-Z](?!.*__)[a-zA-Z0-9_]{3,29}[a-zA-Z0-9]$'


class AuthLogin(BaseModel):
    """Схема представления данных для авторизации пользователя."""

    email: str
    password: str

    @validator('email')
    def validate_email(cls, value: str) -> str:
        """Переводит символы поля email в нижний регистр."""
        return value.lower()


class AuthPasswordChange(BaseModel):
    """Схема представления данных для смены текущего пароля пользователя."""

    password: str
    new_password: str
    new_password_confirm: str

    @validator('new_password')
    def validate_new_password(cls, value: str, values: dict) -> str:
        """Производит валидацию поля 'new_password'."""
        if value == values.get('password'):
            raise ValueError(
                'Прежний и новый пароли должны отличаться'
            )
        errors: list[str] = [
            err_message
            for condition, err_message
            in PASS_CHARS_VALIDATORS.items()
            if not condition(value)
        ]
        if len(errors) > 0:
            raise ValueError(
                'Введите пароль, который удовлетворяет критериям:' +
                ''.join(errors)
            )
        return value

    @validator('new_password_confirm')
    def validate_new_password_confirm(cls, value: str, values: dict) -> str:
        """Производит валидацию поля 'new_password_confirm'."""
        if value != values.get('new_password'):
            raise ValueError(
                'Пароли не совпадают'
            )
        return value


class AuthPasswordReset(BaseModel):
    """
    Схема представления данных для первого этапа
    восстановления пароля: отправка сообщения на почту.
    """

    email: EmailStr

    @validator('email')
    def validate_email(cls, value: str) -> str:
        """
        Переводит символы поля email в нижний регистр.

        Валидация структуры email осуществляется автоматически в Pydantic.
        """
        return value.lower()


class AuthPasswordResetConfirm(BaseModel):
    """
    Схема представления данных для второго этапа
    восстановления пароля: смена пароля пользователя.
    """

    reset_token: str
    new_password: str
    new_password_confirm: str

    @validator('new_password')
    def validate_new_password(cls, value: str, values: dict) -> str:
        """Производит валидацию поля 'new_password'."""
        if value == values.get('password'):
            raise ValueError(
                'Прежний и новый пароли должны отличаться'
            )
        errors: list[str] = [
            err_message
            for condition, err_message
            in PASS_CHARS_VALIDATORS.items()
            if not condition(value)
        ]
        if len(errors) > 0:
            raise ValueError(
                'Введите пароль, который удовлетворяет критериям:' +
                ''.join(errors)
            )
        return value

    @validator('new_password_confirm')
    def validate_new_password_confirm(cls, value: str, values: dict) -> str:
        """Производит валидацию поля 'new_password_confirm'."""
        if value != values.get('new_password'):
            raise ValueError(
                'Пароли не совпадают'
            )
        return value


class AuthRegister(BaseModel):
    """Схема представления данных для регистрации пользователя."""

    name_first: str
    name_last: str
    email: EmailStr
    password: str
    from_referral_code: Optional[str] = None

    @validator('name_first')
    def validate_name_first(cls, value: str) -> str:
        """
        Производит валидацию поля 'name_first'.

        Переводит символы поля в title регистр.
        """
        value: str = cls._validate_user_name(
            value=value,
            err=USER_NAME_FIRST_ERROR,
        )
        return value.title()

    @validator('name_last')
    def validate_name_last(cls, value: str) -> str:
        """
        Производит валидацию поля 'name_last'.

        Переводит символы поля в title регистр.
        """
        value: str = cls._validate_user_name(
            value=value,
            err=USER_NAME_LAST_ERROR,
        )
        return value.title()

    @validator('email')
    def validate_email(cls, value: str) -> str:
        """
        Переводит символы поля email в нижний регистр.

        Валидация структуры email осуществляется автоматически в Pydantic.
        """
        return value.lower()

    @validator('password')
    def validate_password(cls, value: str) -> str:
        """Производит валидацию поля 'password'."""
        errors: list[str] = [
            err_message
            for condition, err_message
            in PASS_CHARS_VALIDATORS.items()
            if not condition(value)
        ]
        if len(errors) > 0:
            raise ValueError(
                'Введите пароль, который удовлетворяет критериям:' +
                ''.join(errors)
            )
        return value

    @validator('from_referral_code')
    def validate_from_referral_code(cls, value: str, values: dict) -> str:
        """Производит валидацию поля 'from_referral_code'."""
        if value is not None and not fullmatch(REFERRAL_CODE_REGEXP, value):
            raise ValueError(
                'Укажите корректный реферальный код, '
                f'состоящий из {REFERRAL_CODE_LEN} символов.'
            )
        return value

    def _validate_user_name(value: str, err: str) -> str:
        """Производит валидацию поля модели для имени или фамилии."""
        value: str = value.strip()
        if (
            not fullmatch(USER_NAME_REGEXP, value) or
            value.startswith('-') or
            value.endswith('-')
        ):
            raise ValueError(err)
        return value


class JwtTokenAccess(BaseModel):
    """Схема представления JWT токена доступа."""

    access: str


class JwtTokenRefresh(BaseModel):
    """Схема представления JWT токена обновления."""

    refresh: str


class UserRegisterRepresent(BaseModel):
    """Схема представления пользователя."""

    id: int
    name_first: str
    name_last: str
    email: EmailStr
    reg_date: datetime
