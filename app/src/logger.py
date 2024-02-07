"""
Модуль инициализации логера.

Используется ColoredFormatter для цветового отображения уровней логирования.
Отступы сообщений от названия уровня логов синхронизированы с системными.
"""

from logging import DEBUG, getLogger, Logger, StreamHandler
import sys
from typing import Literal

from colorlog import ColoredFormatter

FORMAT: Literal = '%(log_color)s%(levelname)-10s%(reset)s%(message)s - %(asctime)s at %(name)s.%(funcName)s(%(lineno)d)'

FORMATTER: ColoredFormatter = ColoredFormatter(
    fmt=FORMAT,
    log_colors={
        'DEBUG': 'cyan',
        'INFO': 'green',
        'WARNING': 'yellow',
        'ERROR': 'red',
        'CRITICAL': 'red,bg_white',
    },
)


def get_stream_handler() -> StreamHandler:
    """Инициализирует обработчик с выводом в консоль."""
    stream_handler = StreamHandler(stream=sys.stderr)
    stream_handler.setFormatter(FORMATTER)
    return stream_handler


def get_logger(name) -> Logger:
    """
    Инициализирует логгер.

    Подключает обработчики:
        - StreamHandler: обработчик с выводом в консоль.
    """
    logger: Logger = getLogger(name)
    logger.setLevel(DEBUG)
    logger.addHandler(get_stream_handler())
    return logger
