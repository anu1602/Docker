FROM ubuntu:xenial
RUN echo "deb apt-key adv --keyserver hkp://keyserver.ubuntu.com:80 --recv-keys 8AA7AF1F1091A5FD" \
&& echo 'deb http://repo.sawtooth.me/ubuntu/1.0/stable xenial universe' >> /etc/apt/sources.list \
&& apt-get update

RUN apt-get install -y --allow-unauthenticated -q python3-grpcio-tools=1.1.3-1 \
    python3-pip \
    python3-sawtooth-rest-api \
    python3-sawtooth-sdk

RUN pip3 install \
    aiohttp \
    aiopg \
    bcrypt \
    itsdangerous \
    pycrypto \
    psycopg2-binary

ENV PATH $PATH:/project/sawtooth-simple-supply/bin

EXPOSE 8008/tcp 
     
     
