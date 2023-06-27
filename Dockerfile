FROM node:18-alpine3.16

WORKDIR /opt/node_app
RUN npm install -g npm@9.7.2

ENV PATH /opt/node_app/node_modules/.bin:$PATH

WORKDIR /opt/node_app/app

COPY . /opt/node_app/app

RUN npm install --save-dev --legacy-peer-deps
RUN npm cache clean --force
RUN npx hardhat compile
RUN node --version

EXPOSE 8545

CMD npx hardhat node
