const express = require("express");
const mysql = require("mysql2");
const cors = require("cors");

const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const session = require('express-session');
const jwt = require('jsonwebtoken');

const bcrypt = require("bcrypt");
const saltRounds = 10;

const app = express();

app.use(express.json());
app.use(cors({
    origin: ["http://localhost:3000"],
    methods: ["GET", "POST"],
    credentials: true
}));

app.use(cookieParser());
app.use(bodyParser.urlencoded({extended: true}));

app.use(session({
    secret: "thisismykey",
    resave: false,
    saveUninitialized: true,
    cookie: {
        expires: 60 * 60 * 24
    } 
}))

const db = mysql.createConnection({
  user: "",
  host: "",
  password: "",
  database: "",
});

app.post("/register", (req, res) => {
  const username = req.body.username;
  const password = req.body.password;

  bcrypt.hash(password, saltRounds, (err, hash) => {
    db.query(
      "INSERT INTO users (username, password) VALUES (?, ?)",
      [username, hash],
      (err, result) => {
        if (err) console.log(err);
      }
    );
  });
});

app.post("/login", (req, res) => {
  const username = req.body.username;
  const password = req.body.password;

  db.query(
    "SELECT * FROM users WHERE username = ?",
    username,
    (err, result) => {
      if (err) {
        res.send({ err: err });
      }

      if (result.length > 0) {
        bcrypt.compare(password, result[0].password, (error, response) => {
            if(response) {
                
                const id = result[0].id;
                const token = jwt.sign({id}, "jwtSecret", {
                    expiresIn: 300,
                })
                
                req.session.user = result;
                res.json({
                    auth: true,
                    token: token, 
                    result: result
                })
            }else{
                res.json({
                    auth: false,
                    message: "wrong username/password"
                })
            }
        })
      } else {
        res.json({
            auth: false,
            message: "no user exist"
        })
      }
    }
  );
});

app.get('/login', (req, res) => {
    if(req.session.user) {
        res.send({loggedIn: true, user: req.session.user})
    }else{
        res.send({loggedIn: false})
    }
})

const verifyJWT = (req, res, next) => {
    const token = req.headers["x-access-token"]
    if(!token) {
        res.send('token is not there!')
    }else{
        jwt.verify(token, 'jwtSecret', (err, decoded) => {
            if(err) {
                res.json({auth: false, message: "failed to authenticate"})
            }else{
                req.userId = decoded.id;
                next()
            }
        })
    }
}

app.get('/isUserAuth', verifyJWT, (req, res) => {
    res.send("You are authenticated")
})

app.listen(3001, () => {
  console.log("running service");
});
