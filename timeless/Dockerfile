FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1

RUN apt-get update && apt-get install -y gcc make
RUN apt-get install tree -y
RUN echo "uoftctf{4_c00k13_4_d4y_k33p5_7h3_h4ck3r5_4w4y_0r_50m37h1n6_l1k3_7h47}" > /flag.txt && \
    chmod 400 /flag.txt && \
    chown root:root /flag.txt

COPY ./src/readflag.c /readflag.c

RUN gcc /readflag.c -o /readflag

RUN rm /readflag.c

RUN chmod 4755 /readflag

WORKDIR /app

COPY ./src/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY ./src .

RUN groupadd -r flask && useradd -r -g flask flask

RUN chown -R flask:flask /app/

USER flask

EXPOSE 5000

CMD ["python", "run.py"]