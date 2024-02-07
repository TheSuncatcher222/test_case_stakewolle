"""
Модуль с задачами для Celery в приложении "auth".
"""

from datetime import datetime

from sqlalchemy.sql.selectable import Select
from sqlalchemy.sql import delete

from src.auth.models import UsedPassResetToken
from src.celery_app import celery_app
from src.database import sync_session_maker
from src.config import DOMAIN_NAME, SUPPORT_EMAIL_TO
from src.user.utils import send_mail


@celery_app.task(name='src.auth.tasks.delete_expired_pass_reset_tokens')
def delete_expired_pass_reset_tokens():
    """
    Удаляет использованные токены восстановления
    пароля с истекшим сроком жизни.
    """
    with sync_session_maker() as session:
        stmt: Select = delete(
            UsedPassResetToken,
        ).where(
            UsedPassResetToken.exp_date < datetime.utcnow(),
        )
        session.execute(stmt)
        session.commit()
    return


@celery_app.task
def send_password_restore_to_mail(link: str) -> None:
    """Отправляет сообщение c ссылкой восстановления пароля пользователю."""
    # TODO: вынести в константы и использовать .format()
    content: str = (
        'Здравствуйте,'
        '\n\n'
        'Вы запросили сброс пароля для вашей учетной записи. '
        'Для завершения процесса, пожалуйста, перейдите по следующей ссылке:'
        '\n\n'
        f'{link}'
        '\n\n'
        'Ссылка будет действительна в течении 24 часов.'
        '\n\n'
        'После перехода по ссылке вы сможете установить новый пароль '
        'для вашей учетной записи.'
        '\n\n'
        'Если вы не инициировали этот запрос, пожалуйста, проигнорируйте '
        'это сообщение или свяжитесь с нами в ответом письме.'
        '\n\n'
        'С уважением,'
        '\n'
        f'Служба поддержки {DOMAIN_NAME}'
    )
    subject: str = f'Сброс пароля учетной записи | {DOMAIN_NAME}'
    send_mail(subject=subject, to=SUPPORT_EMAIL_TO, content=content)
    return


@celery_app.task
def send_password_has_changed_to_mail(username: str) -> None:
    """Отправляет сообщение-оповещение о смене пароля пользователю."""
    # TODO: вынести в константы и использовать .format()
    content: str = (
        f'Здравствуйте, {username}.'
        '\n\n'
        'Уведомляем, что пароль для вашей учетной записи был изменен.'
        '\n\n'
        'Если вы не инициировали этот запрос, пожалуйста, немедленно'
        'свяжитесь с нами в ответом письме.'
        '\n\n'
        'С уважением,'
        '\n'
        f'Служба поддержки {DOMAIN_NAME}'
    )
    subject: str = f'Изменение пароля учетной записи | {DOMAIN_NAME}'

    send_mail(subject=subject, to=SUPPORT_EMAIL_TO, content=content)

    return
