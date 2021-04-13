const jwt = require('jsonwebtoken');
const { jwtSecret } = require("../secrets"); // use this secret!

const restricted = (req, res, next) => {
  /*
    If the user does not provide a token in the Authorization header:
    status 401
    {
      "message": "Token required"
    }

    If the provided token does not verify:
    status 401
    {
      "message": "Token invalid"
    }

    Put the decoded token in the req object, to make life easier for middlewares downstream!
  */

  try {
    
    const token = req.headers.authorization?.split(' ')[2];
    console.log('ab: auth-middleware.js: restricted(): "test token" token:', token)

    if (token) {
      jwt.verify(token, jwtSecret, (err, decodedToken) => {
        if (err) {
          next({
            code: 401,
            message: 'token required'
          }, ...err);
        } else {
          req.decodedToken = decodedToken;
          next();
        }
      });
    } else {
      next({
        code: 401,
        message: 'token invalid'
      });
    }

  } catch (err) {
    next({
      message: 'error validating credentials'
    });
  }
}

const only = role_name => (req, res, next) => {
  /*
    If the user does not provide a token in the Authorization header with a role_name
    inside its payload matching the role_name passed to this function as its argument:
    status 403
    {
      "message": "This is not for you"
    }

    Pull the decoded token from the req object, to avoid verifying it again!
  */

  if ( (req?.decodedToken?.role || '') === role_name) {
    role_name = 'student';
    next();
  } else {
    res.status(403).json({
      message: 'you do not have permission to do that'
    })
  }
}


const checkUsernameExists = (req, res, next) => {
  /*
    If the username in req.body does NOT exist in the database
    status 401
    {
      "message": "Invalid credentials"
    }
  */

  const { username } = req.body;
  
  if (username) {
    next();
  } else {
    res.status(401).json({
      message: 'Invalid credentials'
    });
  }
}


const validateRoleName = (req, res, next) => {
  /*
    If the role_name in the body is valid, set req.role_name to be the trimmed string and proceed.

    If role_name is missing from req.body, or if after trimming it is just an empty string,
    set req.role_name to be 'student' and allow the request to proceed.

    If role_name is 'admin' after trimming the string:
    status 422
    {
      "message": "Role name can not be admin"
    }

    If role_name is over 32 characters after trimming the string:
    status 422
    {
      "message": "Role name can not be longer than 32 chars"
    }
  */

  const  { role_name }  = req.body;
  const trmdRole = role_name.trim();

  if (req?.decodedToken?.role || trmdRole === '') {
    // role_name = 'student';
    next();
  } else if (role_name === 'admin') {
    res.status(422).json({
      message: 'role cannot be admin'
    });
    next();
  } else if (trmdRole.length > 32) {
    res.status(422).json({
      message: 'role name can not be longer than 32 characters'
    });
    next();
  } else {
    role_name = trmdRole;
    next();
  }
}

module.exports = {
  restricted,
  checkUsernameExists,
  validateRoleName,
  only,
}
