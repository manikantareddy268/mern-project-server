const jwt = require('jsonwebtoken');
const bcrypt = require('bycryptjs');
const users = require('../model/Users');

 // https://www.uuidgenerator.net/
 const secret = "58eeb678-a532-421c-8efc-fc0078896f3b";

const authController = {
    login: async (request, response) => {
        try {
            // The body contains username and password because of the express.json()
            // middleware configured inn the server.js
            const { username, password } = request.body;
            // Call Database to fetch user by the email

            const data = await Users.findOne({ email: username });
            if(!data) {
                return response.status(401).json({ message: 'Invalid credentials ' });
            }

            const isMatch = await bcrypt.compare(password, data.password);
            if(!isMatch) {
                return response.status(401).json({ message: 'Invalid credentials ' });
            }
            const user = {
                id: data._id,
                name: data.name,
                email: data.email
            };
            const token = jwt.sign(user, secret, {expiresIn: '1h' });

            response.cookie('jwtToken', token, {
                httpOnly: true,
                secure: true,
                domain: 'localhost',
                path: '/'
            });
            response.json({ user: user, message: 'User authenticated' });
        } catch (error) {
            console.log(error);

            response.status(500).json({ error: 'Internal server error' });
        }
    },

    logout: (request, response) => {
        response.clearCookie('jwtToken');
        response.json({nmessage: 'Logout successfull' });
    },

    isUserLoggedIn: (request, response) => {
        const token = request.cookies.jwtToken;

        if (!token) {
            return response.status(401).json({ message: 'Unauthorised access' });
        }

        jwt.verify(token, secret, (error, user) => {
            if (error) {
                return response.status(401).json({ message: 'Unauthorised access' });
            } else {
                response.json({ message: 'User is logged in', user: user });
            }
        });
    },
};

module.exports = authController;