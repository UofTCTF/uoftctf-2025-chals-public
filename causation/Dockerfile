FROM python:3.14.0a3-slim-bullseye AS app

COPY ./causation.py /app/causation.py
COPY ./flag.txt /app/flag.txt

FROM pwn.red/jail

COPY --from=app / /srv
RUN mkdir -p /srv/app
COPY --chmod=555 ./run /srv/app/run

ENV JAIL_PIDS=40 JAIL_MEM=10M JAIL_TIME=120