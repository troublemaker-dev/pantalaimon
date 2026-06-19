FROM python:3.14-slim-trixie AS builder

RUN mkdir -p /app
RUN apt-get update && apt-get install -y \
    git gcc clang cmake g++ pkg-config python3-dev wget bzip2 \
    libdbus-1-dev libglib2.0-dev libgirepository-2.0-dev libcairo2-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
RUN wget https://gitlab.matrix.org/matrix-org/olm/-/archive/master/olm-master.tar.bz2 \
    && tar -xvf olm-master.tar.bz2 \
    && cd olm-master && make && make PREFIX="/usr" install

RUN pip --no-cache-dir install --upgrade pip setuptools wheel

COPY . /app

RUN pip wheel '.[ui]' --wheel-dir /wheels --find-links /wheels

FROM python:3.14-slim-trixie AS run

COPY --from=builder /usr/lib/libolm* /usr/lib/
COPY --from=builder /wheels /wheels
WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    libgirepository-2.0-0 gir1.2-glib-2.0 libdbus-1-3 dbus \
    && rm -rf /var/lib/apt/lists/*

RUN pip --no-cache-dir install --find-links /wheels --no-index 'pantalaimon[ui]'

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENV DBUS_SESSION_BUS_ADDRESS=unix:path=/tmp/pantalaimon-dbus.sock

VOLUME /data
ENTRYPOINT ["/entrypoint.sh"]
CMD ["-c", "/data/pantalaimon.conf", "--data-path", "/data"]
