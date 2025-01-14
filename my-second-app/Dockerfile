FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

RUN apt-get update && apt-get install -y gcc make
RUN echo "uoftctf{6u355_1_4m_n07_3X73ND1N6_7h3_n3w_f1r3w4ll_6uy'5_c0n7r4c7_317h3r_:(}" > /flag.txt && \
    chmod 400 /flag.txt && \
    chown root:root /flag.txt

RUN pip install flask

COPY ./src/readflag.c /readflag.c

RUN gcc /readflag.c -o /readflag
RUN rm /readflag.c
RUN chmod 4755 /readflag

WORKDIR /app
COPY ./src .

RUN groupadd -r flask && useradd -r -g flask flask

RUN chown -R flask:flask /app/
USER flask

EXPOSE 5000

# Run the application
CMD ["python", "guest_list.py"]