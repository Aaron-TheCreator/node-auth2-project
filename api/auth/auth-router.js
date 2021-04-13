const bcryptjs = require('bcryptjs');
const jwt = require('jsonwebtoken');
const router = require("express").Router();
const { checkUsernameExists, validateRoleName } = require('./auth-middleware');
const Users = require('../users/users-model.js');
const { jwtSecret } = require("../secrets"); // use this secret!

router.post("/register", validateRoleName, async (req, res, next) => {
  /**
    [POST] /api/auth/register { "username": "anna", "password": "1234", "role_name": "angel" }

    response:
    status 201
    {
      "user"_id: 3,
      "username": "anna",
      "role_name": "angel"
    }
   */

  const credentials = req.body;

  try {
    const hash = bcryptjs.hashSync(credentials.password, 10);
    credentials.password = hash;

    const user = await Users.add(credentials);
    const token = generateToken(user);
    res.status(201).json({
       user, token
    })
  } catch (err) {
    console.log(err);
    next({
      message: 'error saving new user', err
    });
  }
});


router.post("/login", checkUsernameExists, async (req, res, next) => {
  /**
    [POST] /api/auth/login { "username": "sue", "password": "1234" }

    response:
    status 200
    {
      "message": "sue is back!",
      "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.ETC.ETC"
    }

    The token must expire in one day, and must provide the following information
    in its payload:

    {
      "subject"  : 1       // the user_id of the authenticated user
      "username" : "bob"   // the username of the authenticated user
      "role_name": "admin" // the role of the authenticated user
    }
   */
  
  const { username, password } = req.body;

  try {
    const [user] = await Users.findBy({ username: username});
    if (user && bcryptjs.compareSync(password, user.password)) {
      const token = generateToken(user);
      res.status(200).json({
        message: `${username} is back!`,
        token: token
      });
    } else {
      next({
        code: 401,
        message: 'invalid credentials'
      });
    }
  } catch (err) {
    next(err);
    // next({
    //   code: 500,
    //   message: 'db error',
    //   ...err
    // });
  }
});

function generateToken(user) {
  console.log(`ab: authRouter.js: generateToken(user): user:`, user)



  // will be passed into jwt.sign(:payload)
  const payload = {
    subject: user.user_id,
    username: user.username,
    role_name: user.role
  };

  // addtl config for headers
  const options = {
    expiresIn: '1d'
  };

  const token = jwt.sign(payload, jwtSecret, options);

  return token;
}

module.exports = router;
