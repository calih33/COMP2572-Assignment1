
require("./utils.js");

require('dotenv').config();
const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const bcrypt = require('bcrypt');
const saltRounds = 12;

const port = process.env.PORT || 3000;

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

var mongoStore = MongoStore.create({
	mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/sessions`,
    crypto: {
                secret: mongodb_session_secret
    }
})

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
	   res.send("<h1 style='color:darkred;'>A NoSQL injection attack was detected!!</h1>");
	   return;
	}	

	const result = await userCollection.find({username: username}).project({username: 1, password: 1, _id: 1}).toArray();

	console.log(result);

    res.send(`<h1>Hello ${username}</h1>`);
});

app.get('/about', (req,res) => {
    var color = req.query.color;

    res.send("<h1 style='color:"+color+";'>Cali Heung</h1>");
});

app.get('/contact', (req,res) => {
    var missingEmail = req.query.missing;
    var html = `
        email address:
        <form action='/submitEmail' method='post'>
            <input name='email' type='text' placeholder='email'>
            <button>Submit</button>
        </form>
    `;
    if (missingEmail) {
        html += "<br> email is required";
    }
    res.send(html);
});

app.post('/submitEmail', (req,res) => {
    var email = req.body.email;
    if (!email) {
        res.redirect('/contact?missing=1');
    }
    else {
        res.send("Thanks for subscribing with your email: "+email);
    }
});

app.get('/', (req, res) => {
	if (req.session.authenticated) {
		const html = `
			<h1>Hello, ${req.session.username}</h1>
			<a href="/members"><button>Go to Members Area</button></a>
			<a href="/logout"><button>Logout</button></a>
		`;
		res.send(html);
	} else {
		const html = `
			<h1>Welcome to My Website</h1>
			<a href="/createUser"><button>Sign Up</button></a>
			<a href="/login"><button>Login</button></a>
		`;
		res.send(html);
	}
});


app.get('/createUser', (req,res) => {
    var html = `
    create user
    <form action='/submitUser' method='post'>
    <input name='name' type='text' placeholder='name'>
    <input name='email' type='email' placeholder='email'>
    <input name='password' type='password' placeholder='password'>
    <button>Submit</button>
    </form>
    `;
    res.send(html);
});


app.get('/login', (req,res) => {
    var html = `
    log in 
    <form action='/loggingin' method='post'>
    <input name='email' type='text' placeholder='email'>
    <input name='password' type='password' placeholder='password'>
    <button>Submit</button>
    </form>
    `;

    res.send(html);
});

app.post('/submitUser', async (req,res) => {
    var name = req.body.name;
    var email = req.body.email;
    var password = req.body.password;

    if (!name || !email || !password) {
        var missingFields = [];
        if (!name) missingFields.push("Name is required </br>");
        if (!email) missingFields.push("Email is required </br>");
        if (!password) missingFields.push("Password is required </br>");
    
        var message = `${missingFields.join('')} <a href='/createUser'>Try Again</a>
        `;
        return res.send(message);
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
	
    await userCollection.insertOne({name: name, email: email, password: hashedPassword});
	console.log("Inserted user");

    res.redirect("/members")
});

app.post('/loggingin', async (req,res) => {
    var email = req.body.email;
    var password = req.body.password;

    const schema = Joi.string().email().required();
	const validationResult = schema.validate(email);
	if (validationResult.error != null) {
	   console.log(validationResult.error);
	   res.redirect("/login");
	   return;
	}

	const result = await userCollection.find({email: email}).project({name: 1, password: 1, _id: 1}).toArray();

	console.log(result);
	if (result.length != 1) {
		console.log("user not found");
		res.redirect("/login");
		return;
	}
	if (await bcrypt.compare(password, result[0].password)) {
		console.log("correct password");
		req.session.authenticated = true;
		req.session.email = email;
        req.session.name = result[0].name;
		req.session.cookie.maxAge = expireTime;

		res.redirect('/loggedin');
		return;
	}
	else {
		console.log("incorrect password");
		res.redirect("/login");
		return;
	}
});

app.get('/loggedin', (req, res) => {
	if (!req.session.authenticated) {
		return res.redirect('/login');
	}
	const html = `
		<h1>Hello, ${req.session.name}!</h1>
		<a href="/members"><button>Go to Members Area</button></a>
		<a href="/logout"><button>Logout</button></a>
	`;
	res.send(html);
});

app.get('/members', (req, res) => {
    if (!req.session.name) {
        res.redirect('/login');
        return;
    }
    const html = `
		<h1>Hello, ${req.session.name}!</h1>
        <img src='/fluffy.gif' style='width:250px;'></br>
		<a href="/logout"><button>Logout</button></a>
	`;
	res.send(html);
});


app.get('/logout', (req, res) => {
    req.session.destroy(); 
    res.redirect('/');       
});


app.use(express.static(__dirname + "/public"));

app.get("*", (req,res) => {
	res.status(404);
	res.send("Page not found - 404");
})

app.listen(port, () => {
	console.log("Node application listening on port "+port);
}); 