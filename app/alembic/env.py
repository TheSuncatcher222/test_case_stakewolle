from logging.config import fileConfig

from alembic import context
from sqlalchemy import engine_from_config
from sqlalchemy import pool

from src.auth.models import Base as BaseAuth
from src.config import Base, DB_HOST, DB_NAME, DB_PASS, DB_PORT, DB_USER
from src.user.models import Base as BaseUser

# this is the Alembic Config object, which provides
# access to the values within the .ini file in use.
config = context.config

# add env data to alembic.ini
section = config.config_ini_section
env_data = {
    'DB_HOST': DB_HOST,
    'DB_NAME': DB_NAME,
    'DB_PASS': DB_PASS,
    'DB_PORT': DB_PORT,
    'DB_USER': DB_USER,
}
for name, value in env_data.items():
    config.set_section_option(section=section, name=name, value=value)


# Interpret the config file for Python logging.
# This line sets up loggers basically.
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# add your model's MetaData object here
# for 'autogenerate' support
# from myapp import mymodel
# target_metadata = mymodel.Base.metadata
target_metadata = Base.metadata

# other values from the config, defined by the needs of env.py,
# can be acquired:
# my_important_option = config.get_main_option("my_important_option")
# ... etc.


def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode.

    This configures the context with just a URL
    and not an Engine, though an Engine is acceptable
    here as well.  By skipping the Engine creation
    we don't even need a DBAPI to be available.

    Calls to context.execute() here emit the given string to the
    script output.

    """
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        process_revision_directives=_process_revision_directives,
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run migrations in 'online' mode.

    In this scenario we need to create an Engine
    and associate a connection with the context.

    """
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            process_revision_directives=_process_revision_directives,
        )

        with context.begin_transaction():
            context.run_migrations()


def _process_revision_directives(context, revision, directives):
    """
    Используется для обнаружения отсутствия изменений
    в конфигурации базы данных с момента последней
    произведенной миграции.
    Необходим для того, чтобы Alembic не генерировал "пустые"
    миграционные файлы.
    """
    if config.cmd_opts.autogenerate:
        script = directives[0]
        if script.upgrade_ops.is_empty():
            directives[:] = []
            print('No migrations to apply.')
    return


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
