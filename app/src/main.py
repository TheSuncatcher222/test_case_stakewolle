"""
Главный модуль FastAPI сервиса.

Осуществляет запуск проекта, подключение базы данных, регистрацию эндпоинтов.
"""

import os
import sys

from fastapi import FastAPI
from fastapi_cache import FastAPICache
from fastapi_cache.backends.redis import RedisBackend
from redis import asyncio as aioredis
from starlette.middleware.cors import CORSMiddleware
import uvicorn

# INFO: добавляет корневую директорию проекта в sys.path для возможности
#       использования абсолютных путей импорта данных из модулей.
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.auth.routers import router_auth
from src.config import (
    ASGI_PORT, DEBUG,
    DOMAIN_IP, DOMAIN_NAME,
    REDIS_HOST, REDIS_PORT,
    WORKERS_AMOUNT,
)
from src.logger import get_logger, Logger
from src.user.routers import router_users

app: FastAPI = FastAPI(
    debug=DEBUG,
    title='Stakewolle test case',
    description='Solution by https://github.com/TheSuncatcher222',
    version='0.1',
    openapi_url='/api/openapi.json',
    docs_url='/api/docs',
    redoc_url='/api/redoc',
)


@app.on_event("startup")
async def startup():
    logger.info("startup")
    redis = aioredis.from_url(
        f'redis://{REDIS_HOST}:{REDIS_PORT}/3',
        encoding="utf8",
        decode_responses=True,
    )
    FastAPICache.init(RedisBackend(redis), prefix="fastapi-cache")


logger: Logger = get_logger(name=__name__)

allowed_origins = [
    'http://localhost:80',
    'http://localhost:8000',
    'http://localhost:8080',
    f'https://{DOMAIN_IP}',
    f'https://{DOMAIN_NAME}',
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

ROUTERS: list[FastAPI] = [
    router_auth,
    router_users,
]

for router in ROUTERS:
    app.include_router(
        router=router,
        prefix='/api'
    )

if __name__ == '__main__':
    """Автозапуск ASGI и сервиса."""
    uvicorn.run(
        app='main:app',
        host='0.0.0.0',
        port=ASGI_PORT,
        reload=True,
        workers=WORKERS_AMOUNT,
    )
