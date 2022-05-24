const jwt = require('jsonwebtoken');
const User = require('../users/users-model');
const { JWT_SECRET } = require("../secrets"); // use this secret!

const restricted = async (req, res, next) => {
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
  if (req.headers.authorization == null) {
    next({ status: 401, message: 'Token required' });
    return;
  }

  try {
    req.decodedJwt = await jwt.verify(req.headers.authorization, JWT_SECRET);
    next();
  } catch(err) {
    next({ status: 401, message: 'Token invalid' });
    return;
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
  try {
    if (req.decodedJwt.role != role_name) {
      next({ status: 403, message: '' });
      return;
    }
    next();
  } catch(err) {
    next({ message: 'internal server error!' });
  }
}


const checkUsernameExists = async (req, res, next) => {
  /*
    If the username in req.body does NOT exist in the database
    status 401
    {
      "message": "Invalid credentials"
    }
  */
  try {
    const user = await User.findBy({'username': req.body.username});
    if (!(user.length > 0)) {
      next({ status: 401, message: 'Invalid credentials' });
      return;
    }
    next();
  } catch(err) {
    next({ message: 'internal server error!' });
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


 // Is role_name valid?
 let { role_name } = req.body;
  if (role_name == null || req.body.role_name.trim() === '') {
    role_name = 'student';
  } else {
    role_name = req.body.role_name.trim();
  }

  if (role_name == 'admin') {
    next({ status: 422, message: 'Role name can not be admin' });
    return;
  }

  if (role_name.length > 32) {
    next({ status: 422, message: 'Role name can not be longer than 32 chars' });
    return;
  }

  req.body.role_name = role_name;
  next();
}

module.exports = {
  restricted,
  checkUsernameExists,
  validateRoleName,
  only,
}
