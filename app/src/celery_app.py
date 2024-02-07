from celery import Celery

from src.config import REDIS_HOST, REDIS_PORT, ONE_DAY_SEC

celery_app: Celery = Celery(
    'tasks',
    backend=f'redis://{REDIS_HOST}:{REDIS_PORT}/0',
    broker=f'redis://{REDIS_HOST}:{REDIS_PORT}/1',
)

celery_app.autodiscover_tasks(
    [
        'src.auth',
        'src.feedback',
    ],
)

celery_app.conf.beat_schedule = {
    'delete_expired_pass_reset_tokens': {
        'task': 'src.auth.tasks.delete_expired_pass_reset_tokens',
        'schedule': ONE_DAY_SEC,  # INFO: время в секундах.
    },
}


"""Priority levels."""

PRIOR_NONE: int = 9

PRIOR_VERY_LOW: int = 8

PRIOR_LOW: int = 7

PRIOR_MEDIUM: int = 5

PRIOR_HIGH: int = 3

PRIOR_VERY_HIGH: int = 2

PRIOR_IMPORTANT: int = 1

PRIOR_MOST_IMPORTANT: int = 0
