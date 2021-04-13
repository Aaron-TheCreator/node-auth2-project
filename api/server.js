const express = require("express");
const helmet = require("helmet");
const cors = require("cors");

const authRouter = require("./auth/auth-router.js");
const usersRouter = require("./users/users-router.js");

const server = express();

server.use(helmet());
server.use(express.json());
server.use(cors());

server.use("/api/auth", authRouter);
server.use("/api/users", usersRouter);

server.get('/', (req, res) => {
  res.status(200).json({
    message: "Welcome to the Auth Example Server!"
  })
})

server.use((err, req, res, next) => { // eslint-disable-line
  const errCode = err.code;
  res.status(errCode || 500).json({
    message: err.message,
    stack: err.stack,
  });
});

module.exports = server;
