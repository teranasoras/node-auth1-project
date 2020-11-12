const express = require("express");
const helmet = require("helmet");
const cors = require("cors");
// we will bring bcrypt onboard
const bcrypt = require('bcryptjs');
const session = require('express-session');
const sessionStore = require('connect-session-knex')(session);

const Users = require('./users/users-model');

const usersRouter = require("./users/users-router");

const server = express();

server.use(helmet());
server.use(express.json());
server.use(cors());
server.use(session({
    name: 'mycookie',
    secret: 'this should come from process.env', // the cookie is encrypted
    cookie: {
      maxAge: 1000 * 60,
      secure: false, // in production do true (https is a must)
      httpOnly: true, // this means the JS on the page cannot read the cookie
    },
    resave: false, // we don't want to recreate sessions that haven't changed
    saveUninitialized: false, // we don't want to persist the session 'by default' (GDPR!!!!)
    // storing the session in the db so it survives server restarts
    store: new sessionStore({
      knex: require('./data/connection.js'),
      tablename: 'sessions',
      sidfieldname: 'sid',
      createTable: true,
      clearInterval: 1000 * 60 * 60,
    }),
  }));
  


server.post('/api/register', async (req, res) => {
    try {
      const { username, password } = req.body;
      //gets these items from the request
      const hash = bcrypt.hashSync(password, 10); 
        //sets the hash for encrypting the password
      const user = { username, password: hash};
      //sets the user to be the username and a hashed password
      const addedUser = await Users.add(user);
      res.json(addedUser);
      //adds the user into the database
    } catch (err) {
      res.status(500).json({ message: err.message });
    }
  })

  server.post('/api/login', async (req, res) => {
    try {
      const [user] = await Users.findBy({ username: req.body.username });
      //finds the user with the matching username
      if (user && bcrypt.compareSync(req.body.password, user.password)) {
        //checks to make sure that the password matches
        req.session.user = user
        res.json({ message: `welcome back, ${user.username}` });
      } else {
        res.status(401).json({ message: 'invalid login' });
      }
    } catch (err) {
      res.status(500).json({ message: err.message });
    }
  })
  
  server.get('/api/logout', (req, res) => {
  if (req.session && req.session.user) {
    req.session.destroy(err => {
      if (err) res.json({ message: 'you can not leave' })
      else res.json({ message: 'good bye' })
    })
  } else {
    res.json({ message: 'you had no session actually!' })
  }
});

server.use("/api/users", usersRouter);

module.exports = server;