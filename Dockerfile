FROM node:18-alpine3.16


RUN apk update \
    && apk add --virtual build-dependencies  \
    build-base  \
    gcc  \
    wget \
    git \
    python3 

WORKDIR /opt/node_app

COPY package*.json ./
RUN npm install --save-dev && npm cache clean --force

ENV PATH /opt/node_app/node_modules/.bin:$PATH

WORKDIR /opt/node_app/app

COPY . /opt/node_app/app

RUN npx hardhat compile

EXPOSE 8545

CMD npx hardhat node & npx hardhat run scripts/deploy.ts --network localhost & sleep infinity & wait