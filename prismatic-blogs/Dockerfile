FROM node:18

WORKDIR /usr/src/app

COPY ./src/package.json ./

RUN npm install --only=production

COPY ./src .

RUN npx prisma generate

EXPOSE 3000

CMD ["node", "index.js"]
