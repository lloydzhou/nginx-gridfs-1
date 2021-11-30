FROM ubuntu:18.04

ENV NGINX_VERSION="1.19.9"

RUN apt update && apt install -y git wget gcc make libmongoc-dev libpcre3-dev libssl-dev zlib1g-dev
RUN wget http://nginx.org/download/nginx-${NGINX_VERSION}.tar.gz -O nginx.tar.gz
RUN tar -xf nginx.tar.gz

ADD . /tmp

RUN pwd && ls

RUN cd nginx-${NGINX_VERSION} && ./configure --add-module=/tmp/nginx-gridfs/ && make install


