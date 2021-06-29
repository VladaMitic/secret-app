require('dotenv').config()
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const session = require('express-session');
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const FacebookStrategy = require("passport-facebook").Strategy;
const findOrCreate = require('mongoose-findorcreate');

const app = express();

app.set('view engine', 'ejs');
app.use(express.static("public"));
app.use(bodyParser.urlencoded({
    extended: true
}));

app.use(session({
    secret: "This is secret code.",
    resave: false,
    saveUninitialized: false,
}));

app.use(passport.initialize());
app.use(passport.session());

mongoose.connect("mongodb://localhost:27017/userDB", {
    useNewUrlParser: true,
    useUnifiedTopology: true,
    useFindAndModify: false
});
mongoose.set("useCreateIndex", true);

const userSchema = new mongoose.Schema({
    username: {
        type: String,
        unique: true
    }, // values: email address, googleId, facebookId
    password: String,
    provider: String, // values: 'local', 'google', 'facebook'
    email: String,
    secret: String
});

userSchema.plugin(passportLocalMongoose, {
    usernameField: "username"
});

userSchema.plugin(findOrCreate);

const User = new mongoose.model("User", userSchema);

passport.use(User.createStrategy());
passport.serializeUser(function (user, done) {
    done(null, user.id);
});

passport.deserializeUser(function (id, done) {
    User.findById(id, function (err, user) {
        done(err, user);
    });
});

passport.use(new GoogleStrategy({
        clientID: process.env.CLIENT_ID,
        clientSecret: process.env.CLIENT_SECRET,
        callbackURL: "http://localhost:3000/auth/google/secrets",
        userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
    },
    function (accessToken, refreshToken, profile, cb) {
        User.findOrCreate({
                username: profile.id
            }, {
                provider: "google",
                email: profile._json.email
            },
            function (err, user) {
                return cb(err, user);
            }
        );
    }
));

passport.use(new FacebookStrategy({
        clientID: process.env.FACEBOOK_APP_ID,
        clientSecret: process.env.FACEBOOK_APP_SECRET,
        callbackURL: "http://localhost:3000/auth/facebook/secrets",
        profileFields: ["id", "email"]
    },
    function (accessToken, refreshToken, profile, cb) {
        User.findOrCreate({
                username: profile.id
            }, {
                provider: "facebook",
                email: profile._json.email
            },
            function (err, user) {
                return cb(err, user);
            }
        );
    }
));

app.get("/", function (req, res) {
    res.render("home");
});

app.get("/auth/google/secrets",
    passport.authenticate("google", {
        failureRedirect: "/login"
    }),
    function (req, res) {
        res.redirect("/secrets");
    }
);

app.get("/auth/facebook/secrets",
    passport.authenticate("facebook", {
        failureRedirect: "/login"
    }),
    function (req, res) {
        // Successful authentication, redirect home.
        res.redirect("/secrets");
    }
);

app.get('/auth/google',
    passport.authenticate('google', {
        scope: ['profile', 'email']
    })
);

app.get("/auth/facebook",
    passport.authenticate("facebook", {
        scope: ["email"]
    })
);

app.get("/secrets", function (req, res) {
    User.find({"secret": {$ne: null}}, function(err, foundUsers) {
        if(err) {
            console.log(err);
        } else {
            if(foundUsers) {
                res.render("secrets", {usersWithSecrets: foundUsers});
            }
        }
    });
});

app.route("/submit")
    .get(function (req, res) {
        if (req.isAuthenticated()) {
            res.render("submit");
        } else {
            res.redirect("/login");
        }
    })
    .post(function (req, res) {
        const submitedSecret = req.body.secret;
        console.log(req.user);
        User.findById(req.user.id, function (err, foundUser) {
            if (err) {
                console.log(err);
            } else {
                if (foundUser) {
                    foundUser.secret = submitedSecret;
                    foundUser.save(function () {
                        res.redirect("/secrets");
                    });
                }
            }
        });
    });

app.get("/logout", function (req, res) {
    req.logout();
    res.redirect("/login");
});

app.route('/register')
    .get(function (req, res) {
        res.render('register');
    })
    .post(function (req, res) {
        const username = req.body.username;
        const password = req.body.password;

        User.register({
            username: username,
            email: username,
            provider: 'local'
        }, password, function (err, user) {
            if (err) {
                console.log(err);
                res.redirect('/register');
            } else {
                passport.authenticate('local')(req, res, function () {
                    res.redirect('/secrets');
                });
            }
        });
    });

app.route("/login")
    .get(function (req, res) {
        res.render("login");
    })
    .post(function (req, res) {
        const user = new User({
            username: req.body.username,
            password: req.body.password
        });

        req.login(user, function (err) {
            if (err) {
                console.log(err);
            } else {
                passport.authenticate("local")(req, res, function () {
                    res.redirect("/secrets");
                });
            }
        });
    });

app.listen(3000, function () {
    console.log("Server has started");
});