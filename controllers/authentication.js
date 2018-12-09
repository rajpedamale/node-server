const User = require('../models/user');
const jwt = require('jwt-simple');
const config = require('../config');

function tokenForUser(user) {
    const timestamp = new Date().getTime();
    return jwt.encode({ sub: user.id, iat: timestamp }, config.secret);
}

exports.signin = function (req, res, next) {
    // User has already had their email and password auth'd
    // return the token

    res.send({ token: tokenForUser(req.user) });
};

exports.signup = function (req, res, next) {
    const email = req.body.email;
    const password  = req.body.password;

    if (!email || !password) {
        return res.status(422).send({ error: 'You must provide email and password' });
    }

    // See if a user with given email exists
    User.findOne({ email: email }, (err, existingUser) => {
        if (err) { return next(err); }

        // if exists, return error
        if (existingUser) {
            return res.status(422).send({ error: 'Email is already registered' });
        }

        // if not, create and save user record
        const user = new User({
            email: email,
            password: password
        });
        user.save(err => {
            if (err) { return next(err);}

            // respond to request indicating the user was created
            res.json({ token: tokenForUser(user) });
        });

    });
};