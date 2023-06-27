FROM node:lts-slim

WORKDIR /opt/node_app
RUN npm install -g npm@9.7.2

ENV PATH /opt/node_app/node_modules/.bin:$PATH

COPY . .

RUN npm install --save-dev --legacy-peer-deps
RUN npm cache clean --force
RUN npx hardhat compile --show-stack-traces
RUN echo $?

EXPOSE 8545

CMD npx hardhat node
