"""
Модуль соединения с базой данных через SQLAlchemy.
"""

from typing import AsyncGenerator

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.asyncio import (
    AsyncEngine, AsyncSession, async_sessionmaker,
    create_async_engine,
)

from src.config import DB_HOST, DB_NAME, DB_PASS, DB_PORT, DB_USER, DEBUG_DB

DATABASE_ASYNC_URL: str = f'postgresql+asyncpg://{DB_USER}:{DB_PASS}@{DB_HOST}:{DB_PORT}/{DB_NAME}'
DATABASE_SYNC_URL: str = f'postgresql+psycopg2://{DB_USER}:{DB_PASS}@{DB_HOST}:{DB_PORT}/{DB_NAME}'


async_engine: AsyncEngine = create_async_engine(
    url=DATABASE_ASYNC_URL,
    echo=DEBUG_DB,
)

async_session_maker: async_sessionmaker = async_sessionmaker(
    bind=async_engine,
    expire_on_commit=False,
)


async def get_async_session() -> AsyncGenerator[AsyncSession, None]:
    async with async_session_maker() as session:
        yield session


sync_engine = create_engine(
    url=DATABASE_SYNC_URL,
    echo=DEBUG_DB,
)

sync_session_maker: sessionmaker = sessionmaker(bind=sync_engine)
