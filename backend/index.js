const express = require('express');
const mongoose = require('mongoose');
const bodyparser = require('body-parser');
const cookieParser = require('cookie-parser');
const User = require('./models/user');
const db = require('./config/config').get(process.env.NODE_ENV);
const { auth } = require('./middleware/auth');

const app = express();

// app use
app.use(bodyparser.urlencoded({ extended: false }));
app.use(bodyparser.json());
app.use(cookieParser());

// database connection
mongoose.Promise = global.Promise;
mongoose.connect(db.DATABASE, { useNewUrlParser: true, useUnifiedTopology: true }, function (err) {
    if (err) console.log(err);
    console.log('database is connected');
});

// adding new user (sign-up route)
app.post('/api/register', async function (req, res) {
    const newuser = new User(req.body);

    if (newuser.password != newuser.password2) return res.status(400).json({ message: 'password not match' });

    const user = await User.findOne({ email: newuser.email });

    if (user) return res.status(200).json({ message: 'User already exists' });

    try {
        await newuser.save();
        return res.status(200).json({ message: 'user created' });
    } catch (error) {
        return res.status(400).json({ success: false, message: error.message });
    }
});

// login user
app.post('/api/login', async function (req, res) {
    const token = req.cookies.auth;

    try {
        const user = await User.findByToken(token);
        if (user) {
            return res.status(400).json({
                error: true,
                message: 'You are already logged in'
            });
        }
    } catch (error) {
        return res.status(400).json({
            error: true,
            message: error.message
        });
    }

    try {
        const user = await User.findOne({ email: req.body.email });
        if (!user) return res.json({ isAuth: false, message: 'Auth failed, email not found' });

        const isMatch = await user.comparepassword(req.body.password);
        if (!isMatch) return res.json({ isAuth: false, message: "password doesn't match" });

        return res.json({ isAuth: true, user });
    } catch (error) {
        return res.status(400).json({
            error: true,
            message: error.message
        });
    }
});

// logout user
app.get('/api/logout', auth, async function (req, res) {
    try{
        await req.user.deleteToken(req.token);
        return res.status(200).json({
            isAuth: false,
            message: 'Logged out successfully'
        });
    }catch(error){
        return res.status(400).json({
            error: true,
            message: error.message
        });
    }
});

// get logged in user
app.get('/api/profile', auth, function (req, res) {
    res.json({
        isAuth: true,
        id: req.user._id,
        email: req.user.email,
        name: req.user.firstname + req.user.lastname
    });
});

app.get('/', function (req, res) {
    res.status(200).send('Welcome to login , sign-up api');
});

// listening port
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`app is live at ${PORT}`);
});