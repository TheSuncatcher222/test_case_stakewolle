FROM python:3.11-slim

LABEL description="Stakewolle: backend" \
      version="0.1" \
      maintainer="https://github.com/TheSuncatcher222"

RUN apt-get update && \
    apt-get install -y postgresql-client && \
    apt-get install -y dos2unix

WORKDIR /app

RUN pip install --upgrade pip

COPY requirements.txt .

RUN pip install -r requirements.txt --no-cache-dir

COPY . .

RUN chmod 777 run_fastapi.sh
