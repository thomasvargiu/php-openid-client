FROM php:7.3.6-fpm-alpine3.9

MAINTAINER Thomas Vargiu, thomas.vargiu@facile.it

ENV LANG C.UTF-8
ENV LC_ALL C.UTF-8

RUN apk add --no-cache \
    bash \
    git \
    gmp
RUN set -ex \
    && apk add --no-cache --virtual build-dependencies \
        autoconf \
        make \
        g++ \
        gmp-dev \
    && docker-php-ext-install -j$(getconf _NPROCESSORS_ONLN) \
        gmp \
    && pecl install -o xdebug-2.7.0 && docker-php-ext-enable xdebug \
    && apk del build-dependencies

RUN set -o pipefail && curl -sS https://getcomposer.org/installer | php -- --install-dir=/usr/local/bin --filename=composer
