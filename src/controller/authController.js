const jwt = require('jsonwebtoken');

 // https://www.uuidgenerator.net/
 const secret = "58eeb678-a532-421c-8efc-fc0078896f3b";

const authController = {
    login: (request, response) => {
        // The body contains username and password because of the express.json()
        // middleware configured inn the server.js
        const { username, password } = request.body;

        if (username === 'admin' && password === 'admin') {
            const user = {
                name: 'John Cena',
                email: 'john@cena'
            };

            const token = jwt.sign(user, secret, {expiresIn: '1h'});
            response.cookie('jwtToken', token, {
                httpOnly: true,
                secure: true,
                domain: 'localhost',
                path: '/'
            });
            response.json({ user: user, message: 'User authenticated' });
        } else {
            response.status(401).json({ message: 'Invalid credentials' });
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