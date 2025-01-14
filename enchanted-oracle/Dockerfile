FROM python:3.10.12-slim-bullseye AS app

RUN pip install --no-cache-dir pycryptodome

COPY ./src/aes-cbc.py /app/aes-cbc.py
COPY ./flag.txt /app/flag.txt
COPY ./src/generate-key.py /app/generate-key.py

RUN python /app/generate-key.py

FROM pwn.red/jail

COPY --from=app / /srv
RUN mkdir -p /srv/app
COPY --chmod=555 ./run /srv/app/run

ENV JAIL_PIDS=40 JAIL_MEM=10M JAIL_TIME=1800
