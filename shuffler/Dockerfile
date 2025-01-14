FROM python:3.11.3-slim-bullseye as app

RUN pip install pycryptodome

WORKDIR /challenge

COPY shuffler.py .

RUN useradd -u 1000 ctfuser

FROM pwn.red/jail
COPY --from=app / /srv

RUN mkdir -p /srv/app

COPY --chmod=555 ./run /srv/app/run

ENV JAIL_PIDS=40 JAIL_MEM=100M JAIL_TIME=120
