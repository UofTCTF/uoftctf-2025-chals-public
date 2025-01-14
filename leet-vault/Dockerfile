FROM node:18-slim

WORKDIR /usr/src/app

COPY ./src/package.json ./
RUN npm install

COPY ./src .

RUN mv ./secret-flag ./node_modules/secret-flag

EXPOSE 1337

CMD [ "node", "5up3r_53cur3_50urc3_c0d3.js" ]
