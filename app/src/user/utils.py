"""
Модуль с вспомогательными функциями приложения "user".
"""
from datetime import datetime, timedelta
import random
import string

from email.message import EmailMessage
import smtplib

from src.config import DEBUG_EMAIL, SMTP_HOST, SMTP_PASSWORD, SMTP_PORT, SMTP_PROTOCOL, SMTP_USER


def generate_referral_code(user_register_dt: datetime) -> str:
    """
    Генерирует уникальный реферальный код
    на основании точного времени и даты регистрации пользователя
    с добавлением текущего времени.

    Возвращает реферальный код. Дата истечения устанавливается
    автоматически в базе данных.
    """
    now_seconds: int = datetime.now().timestamp()
    new_datetime: datetime = user_register_dt + timedelta(seconds=now_seconds)
    str_datetime: str = new_datetime.strftime('%y_%m_%d_%H_%M_%S_%f')
    list_str: list[str] = str_datetime.split('_')
    list_str.extend(
        [
            random.choice(string.ascii_letters) for _ in range(len(list_str))
        ]
    )
    random.shuffle(list_str)
    return ''.join(list_str)


def send_mail(content: str, subject: str, to: str) -> None:
    """Отправляет сообщение пользователю на электронную почту."""
    email: EmailMessage = EmailMessage()
    email['Subject'] = subject
    email['From'] = SMTP_USER
    email['To'] = to
    email.set_content(content)

    if DEBUG_EMAIL:
        with open(f'email_messages_debug/{datetime.now().strftime(format="%Y-%m-%d_%H-%M-%S")}', 'w+') as file:
            file.write(content)
        return

    if SMTP_PROTOCOL == 'TLS':
        with smtplib.SMTP(host=SMTP_HOST, port=SMTP_PORT) as smtp:
            smtp.starttls()
            smtp.login(user=SMTP_USER, password=SMTP_PASSWORD)
            smtp.send_message(email)
    else:
        with smtplib.SMTP_SSL(host=SMTP_HOST, port=SMTP_PORT) as smtp:
            smtp.login(user=SMTP_USER, password=SMTP_PASSWORD)
            smtp.send_message(email)

    return
