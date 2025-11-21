// Create a new router
const bcrypt = require('bcrypt');
const express = require("express")
const router = express.Router()

router.get('/register', function (req, res, next) {
    res.render('register.ejs')
})

router.post('/registered', function (req, res, next) {

    const saltRounds = 10;
    const plainPassword = req.body.password;

    bcrypt.hash(plainPassword, saltRounds, function(err, hashedPassword) {
        if (err) {
            return next(err);
        }

        const sql = `
            INSERT INTO users (first, last, email, password)
            VALUES (?, ?, ?, ?)
        `;

        const values = [
            req.body.first,
            req.body.last,
            req.body.email,
            hashedPassword,
        ];

        req.db.query(sql, values, function(err, result) {
            if (err) {
                return next(err);
            }

            res.send(
                'Hello ' + req.body.first + ' ' + req.body.last +
                ', you are now registered with a secure password!'
            );
        });
    });
});

router.get('/list', function(req, res, next) {
    const sql = 'SELECT first, last, email FROM users';

    req.db.query(sql, function(err, result) {

        if (err) {
            return next(err);
        }
        res.render('listusers.ejs', {users: result});
    });
});

router.get('/login', function(req, res, next) {
    res.render('login.ejs');
});

router.post('/loggedin', function(req, res, next) {
    const email = req.body.email;
    const password = req.body.password;

    const sql = 'SELECT * FROM users WHERE email = ?';

    req.db.query(sql, [email], function(err, result) {
        if (err) {
            return next(err);
        }

        if (result.length === 0) {
            res.send('User not found');
        } else {
            const hashedPassword = result[0].password;

            bcrypt.compare(password, hashedPassword, function(err, match) {
                if (err) {
                    return next(err);
                }

                if (match) {
                    res.send('Login successful!');
                } else {
                    res.send('Incorrect password');
                }
            });
        }
    });
});




// Export the router object so index.js can access it
module.exports = router
