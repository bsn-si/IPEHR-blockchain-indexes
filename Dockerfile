FROM node:18.12.1-alpine3.17

RUN apk --update --no-cache add curl

WORKDIR /opt/node_app
RUN npm install -g npm@9.7.2

ENV PATH /opt/node_app/node_modules/.bin:$PATH

WORKDIR /opt/node_app/app

COPY . .

RUN npm install --save-dev --legacy-peer-deps
RUN npm cache clean --force
RUN npx hardhat compile

EXPOSE 8545

CMD npx hardhat node
