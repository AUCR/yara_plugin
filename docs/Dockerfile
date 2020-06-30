FROM python:3.8.3-alpine3.12
RUN apk update --no-cache
RUN apk add --no-cache \
    suricata

ENV YARA_VERSION 4.0.2

RUN apk add --no-cache \
    openssl \
    file \
    jansson \
    bison \
    python3 \
    tini \
    su-exec

RUN apk add --no-cache -t .build-deps \
    py-setuptools \
    openssl-dev \
    jansson-dev \
    python3-dev \
    build-base \
    libc-dev \
    file-dev \
    automake \
    autoconf \
    libtool \
    flex \
    git \
  && set -x \
  && echo "Install Yara from source..." \
  && cd /tmp/ \
  && git clone --recursive --branch v$YARA_VERSION https://github.com/VirusTotal/yara.git \
  && cd /tmp/yara \
  && ./bootstrap.sh \
  && sync \
  && ./configure --with-crypto \
                 --enable-magic \
                 --enable-cuckoo \
                 --enable-dotnet \
  && make \
  && make install \
  && echo "Install yara-python..." \
  && cd /tmp/ \
  && git clone --recursive --branch v$YARA_VERSION https://github.com/VirusTotal/yara-python \
  && cd yara-python \
  && python setup.py build --dynamic-linking \
  && python setup.py install \
  && rm -rf /tmp/* \
  && apk del --purge .build-deps

RUN adduser -D aucr

ENV FLASK_APP=aucr.py



RUN apk update
RUN apk upgrade

RUN apk add --no-cache \
    gcc \
    libc-dev \
    musl-dev \
    linux-headers \
    libffi-dev \
    py-pillow \
    python3-dev \
    openssl \
    file \
    jansson \
    bison \
    tini \
    su-exec \
    g++ \
    lapack-dev \
    gfortran \
    build-base \
    git \
    p7zip \
    postgresql-dev \
  && pip3 install psycopg2-binary python-dotenv \
  && cd /opt/ && git clone https://github.com/aucr/aucr aucr && cd /opt/aucr \
  && cd /opt/aucr/aucr_app/plugins && git clone https://github.com/aucr/yara_plugin && git clone https://github.com/aucr/unum && cd /opt/aucr \
  && pip3 install -r /opt/aucr/requirements.txt \
  && apk del --purge gcc \
    libc-dev \
    musl-dev \
    linux-headers \
    libffi-dev \
    py-pillow \
    gfortran \
    g++ \
    python3-dev \
    build-base \
    gcc \
    git

WORKDIR /opt/aucr
RUN chmod a+x /opt/aucr/boot.sh
RUN chown -R aucr:aucr /opt/
USER aucr

EXPOSE 5000

ENTRYPOINT ["./boot.sh"]
