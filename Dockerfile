FROM node:18-alpine3.16


RUN apk update \
    && apk add --virtual build-dependencies  \
    build-base  \
    gcc  \
    wget \
    git \
    python3 \
    curl

WORKDIR /opt/node_app
RUN npm install -g npm@9.6.4

ENV PATH /opt/node_app/node_modules/.bin:$PATH

WORKDIR /opt/node_app/app

COPY . /opt/node_app/app

RUN npm install --save-dev --legacy-peer-deps
RUN npm cache clean --force
RUN npx hardhat compile

EXPOSE 8545

CMD npx hardhat node
