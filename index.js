
require("./utils.js");

require('dotenv').config();
const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const bcrypt = require('bcrypt');
const saltRounds = 12;
const port = process.env.PORT || 3000;
const path = require('path');

const app = express();

const Joi = require("joi");

var users = [];

const expireTime = 24 * 60 * 60 * 1000;

/* secret information section */
const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_database = process.env.MONGODB_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;

const node_session_secret = process.env.NODE_SESSION_SECRET;

var {database} = include('databaseConnection');

const userCollection = database.db(mongodb_database).collection('users');

app.use(express.urlencoded({extended: false}));
app.set('view engine', 'ejs');


var mongoStore = MongoStore.create({
	mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/sessions`,
    crypto: {
                secret: mongodb_session_secret
    }
})

function isValidSession(req) {
    if (req.session.authenticated) {
        return true;
    }
    return false;
}

function sessionValidation(req,res,next) {
    if (isValidSession(req)) {
        next();
    }
    else {
        res.redirect('/login');
    }
}

function isAdmin(req) {
    if (req.session.user_type == 'admin') {
        return true;
    }
    return false;
}

function adminAuthorization(req, res, next) {
    if (!isAdmin(req)) {
        res.status(403);
        res.render("errorMessage", {error: "Not Authorized"});
        return;
    }
    else {
        next();
    }
}

app.use(session({ 
    secret: node_session_secret,
	store: mongoStore, 
	saveUninitialized: false, 
	resave: true
}
));

app.get('/nosql-injection', async (req,res) => {
	var username = req.query.user;

	if (!username) {
		res.send(`<h3>no user provided - try /nosql-injection?user=name</h3> <h3>or /nosql-injection?user[$ne]=name</h3>`);
		return;
	}
	console.log("user: "+username);

	const schema = Joi.string().max(20).required();
	const validationResult = schema.validate(username);

	//If we didn't use Joi to validate and check for a valid URL parameter below
	// we could run our userCollection.find and it would be possible to attack.
	// A URL parameter of user[$ne]=name would get executed as a MongoDB command
	// and may result in revealing information about all users or a successful
	// login without knowing the correct password.
	if (validationResult.error != null) {  
	   console.log(validationResult.error);
       res.redirect("/login")
	   return;
	}	

	const result = await userCollection.find({username: username}).project({username: 1, password: 1, _id: 1}).toArray();

	console.log(result);

    res.send(`<h1>Hello ${username}</h1>`);
});

app.get('/about', (req,res) => {
    var color = req.query.color;

    res.render("about", {color: color});
});

app.get('/contact', (req,res) => {
    var missingEmail = req.query.missing;
    res.render("contact", {missing: missingEmail});
});

app.post('/submitEmail', (req,res) => {
    var email = req.body.email;
    if (!email) {
        res.redirect('/contact?missing=1');
    }
    else {
        res.render("submitEmail", {email: email});
    }
});

app.get('/', (req, res) => {
    if (req.session.authenticated && req.session.name) {
        res.render("index", { name: req.session.name });
    } else {
        res.render("index", { name: null });
    }
});





app.get('/createUser', (req,res) => {
    res.render("createUser");
});


app.get('/login', (req,res) => {
    res.render("login");
});

app.post('/submitUser', async (req, res) => {
    var name = req.body.name;
    var email = req.body.email;
    var password = req.body.password;

    let errors = [];
    if (!name) errors.push("Name");
    if (!email) errors.push("Email");
    if (!password) errors.push("Password");

    if (errors.length > 0) {
        return res.render("errorMessage", { error: errors.join(', ') });
    }

	const schema = Joi.object(
		{
			name: Joi.string().alphanum().max(20).required(),
            email: Joi.string().email().required(),
			password: Joi.string().max(20).required()
		});
	
	const validationResult = schema.validate({name, email, password});
	if (validationResult.error != null) {
	   console.log(validationResult.error);
       res.send(`<a href='/createUser'>Try Again</a>`);
	   return;
   }

    var hashedPassword = await bcrypt.hash(password, saltRounds);
	
    var hashedPassword = await bcrypt.hash(password, saltRounds);
    await userCollection.insertOne({name: name, email: email, username: email, password: hashedPassword});
    
    req.session.authenticated = true;
    req.session.name = name;
    req.session.username = email;
    req.session.user_type = 'user';
    req.session.cookie.maxAge = expireTime;

    res.redirect("/"); 
});


app.post('/loggingin', async (req, res) => {
    var email = req.body.email;
    var password = req.body.password;

    const result = await userCollection.find({ email: email }).project({
        username: 1,
        password: 1,
        user_type: 1,
        name: 1,
        _id: 1
    }).toArray();

    if (result.length !== 1) {
        res.redirect("/login");
        return;
    }

    if (await bcrypt.compare(password, result[0].password)) {
        req.session.authenticated = true;
        req.session.name = result[0].name; 
        req.session.user_type = result[0].user_type;
        req.session.cookie.maxAge = expireTime;

        res.redirect('/'); 
    } else {
        res.render("error");
    }
});

app.get('/loggedin', sessionValidation, (req, res) => {
	if (!req.session.authenticated) {
		return res.redirect('/login');
	}
    res.redirect('/members');
});

app.get('/members', (req, res) => {
    if (!req.session.name) {
        res.redirect('/login');
        return;
    }
    res.render('member', { name: req.session.name });
});


app.get('/loggedin/info', (req,res) => {
    res.render("loggedin-info");
});


app.get('/logout', (req, res) => {
    req.session.destroy(() => {
        res.redirect('/');
    });
});

app.get('/admin', sessionValidation, adminAuthorization, async (req, res) => {
    const result = await userCollection.find().project({
        username: 1,
        name: 1,
        user_type: 1,
        _id: 1
    }).toArray();

    res.render("admin", { users: result });
});




app.get('/promote/:username', adminAuthorization, async (req, res) => {
    const username = req.params.username;
    try {
        await userCollection.updateOne(
            { username: username },
            { $set: { user_type: 'admin' } }
        );
        res.redirect('/admin');  
    } catch (err) {
        console.log(err);
        res.render('Error!');
    }
});

app.get('/demote/:username', adminAuthorization, async (req, res) => {
    const username = req.params.username;
    try {
        await userCollection.updateOne(
            { username: username },
            { $set: { user_type: 'user' } }
        );
        res.redirect('/admin'); 
    } catch (err) {
        console.log(err);
        res.send('Error!');
    }
});


app.use(express.static(__dirname + "/public"));

app.get("*", (req,res) => {
	res.status(404);
	res.render("404");
})

app.listen(port, () => {
	console.log("Node application listening on port "+port);
}); 