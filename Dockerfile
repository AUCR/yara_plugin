FROM python:3.6-alpine AS yara

MAINTAINER Wyatt Roersma <wyatt@aucr.io>

ENV YARA_VERSION 3.8.1

RUN apk add --no-cache \
    openssl \
    file \
    jansson \
    bison \
    python \
    tini \
    su-exec

RUN apk add --no-cache -t .build-deps \
    py-setuptools \
    openssl-dev \
    jansson-dev \
    python-dev \
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
