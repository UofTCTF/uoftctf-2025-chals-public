FROM ubuntu:latest AS app

WORKDIR /app/
COPY ./src/baby-pwn.c /app/baby-pwn.c
COPY ./src/baby-pwn /app/baby-pwn
COPY ./flag.txt /app/flag.txt

FROM pwn.red/jail

COPY --from=app / /srv
RUN mkdir -p /srv/app
COPY --chmod=555 ./run /srv/app/run

ENV JAIL_PIDS=40 JAIL_MEM=10M JAIL_TIME=120
