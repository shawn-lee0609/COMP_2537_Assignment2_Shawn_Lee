require('dotenv').config();

const express = require('express');
const session = require('express-session');

// A module for a mongoDB database so that users information can be stored
// and don't need to be asked again.
const MongoStore = require('connect-mongo');

// A module to bcrpyt(hash the pw).
const bcrypt = require('bcrypt');

// Generally 12 is adequate. If the round is too high, it takes more time.
const saltRounds = 12;

// Install Joi module to check the data which is sent from the user is valid or not.
const Joi = require('joi');

// Make an express object
const app = express();

const url = require('url');

app.set('view engine', 'ejs');

// Allows for images, CSS, JS file to be included inyour website.
// 이 코드가 없으면 image file 불러오는게 안됨.
app.use(express.static(__dirname + "/public"));

// Set up the time of the duration of the session.
// This code means that session expires after 1 hour.
const expireTime = 60 * 60 * 1000;

// process.env. lets to access .env file so that it can fetch value(cf. .env).
const port = process.env.PORT || 3000;

// Secret section(since the info is in env file others will not know
// the important information of the server)
const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_db = process.env.MONGODB_DB;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;

const node_session_secret = process.env.SESSION_SECRET;

// Users and Passwords arrays of objects (in memory 'database')
// Need to change this to connect with mongoDB
var { database } = require('./databaseConnection');

// Sets the location of the database when the new user is created.
const userCollection = database.db(mongodb_db).collection('users');

// Middleware for to use req.body it is necessary to parse the data.
// Otherwise req.body will be undefined.
app.use(express.urlencoded({ extended: false }));

// Need to use the information in the .env file which is defined in the secret section
// (e.g. ${mongodb_user}:${mongodb_password}@${mongodb_host}/${mongodb_db})
var mongoStore = MongoStore.create({
    mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/sessionDB`,

    crypto: {
        secret: mongodb_session_secret
    }
});

app.use(session({
    secret: node_session_secret,
    // Decide where to store the session data
    store: mongoStore, // default is memory store (server side)
    saveUninitialized: false,
    resave: true
}));

const navLinks = [
    { name: "Home", link: "/" },
    { name: "Cats", link: "/members" },
    { name: "Login", link: "/login" },
    { name: "Admin", link: "/admin" },
    { name: "404", link: "/*" }
]

app.use('/', (req, res, next) => {
    let path = req.path;
    if (path.length > 1 && path.endsWith('/')) {
        path = path.slice(0, -1);
    }

    res.locals.navLinks = navLinks;
    res.locals.currentURL = path;
    next();
});

// Routes (root homepage)
app.get('/', (req, res) => {

    const username = req.session.username;

    if (!req.session.authenticated) {
        res.render("index");
    }
    else {
        res.render("root(loged in)", { username: username });
    }
});

// Prevent NOSQL injection
// Using Asynchronous since MongoDB data lookup operation is Asynchronous.
// You can only use await inside the "async" function.
app.get('/nosql-injection', async (req, res) => {
    var username = req.query.user;

    if (!username) {
        res.send(`<h3>no user provided - try /nosql-injection?user=name</h3> <h3>or /nosql-injection?user[$ne]=name</h3>`);
        return;
    }
    console.log("user: " + username);

    // It checks the input of the user whether it follows the conditon below.
    // e.g. Make sure it to be a string, max 20 char, and required.

    // 만약 URL에 nosql-injection?user[$ne]=null 과 같이 입력된다면,
    // $ne는 'not equal(같지 않음)'을 의미하는 MongoDB 연산자로, 입력값이 "객체" 형태로 처리되게 된다.
    // 이 경우, user != null 조건이 되어 모든 사용자가 반환될 수 있으며,
    // 이는 인증 우회 등의 보안상 심각한 문제가 발생할 수 있다.
    //
    // 하지만 이 코드에서는 Joi 모듈을 사용하여 유저 입력값을 검증하게 되고,
    // 이 코드에서 Joi는 username이 string 타입이며, 최대 20자이고 반드시 입력되어야 한다는 조건을 
    // 설정해두었기 때문에, 객체 형태인 {$ne: null}은 문자열로 간주되지 않아 유효성 검사에서 걸리게 되는 것이다.
    // 결과적으로 Joi가 에러를 반환하고, NoSQL 인젝션을 방어할 수 있게 되는 것이다.
    // 요약하자면: Joi는 입력이 문자열(string)이 아닌 객체($ne 등)일 경우 유효하지 않은 입력으로 판단해서 
    // NoSQL 인젝션을 막아준다.
    const schema = Joi.string().max(20).required();
    const validationResult = schema.validate(username);

    //If we didn't use Joi to validate and check for a valid URL parameter below
    // we could run our userCollection.find and it would be possible to attack.
    // A URL parameter of user[$ne]=name would get executed as a MongoDB command
    // and may result in revealing information about all users or a successful
    // login without knowing the correct password.

    // If there is an error, it returns.
    if (validationResult.error != null) {
        console.log(validationResult.error);
        res.send("<h1 style='color:darkred;'>A NoSQL injection attack was detected!!</h1>");
        return;
    }

    // Wait until it fetches the data we need.
    // If we don't use "await", it means that it will not wait until it fetches the result.
    // This results of returning a "Promise" object and letting the result as "Promise { <pending> }"
    // which means it does not have any result yet.
    // In other words,
    // If we don't use "await", the function will not wait for the result.
    // Instead, it will return a "Promise" object like Promise { <pending> },
    // which means the data is not ready yet.
    const result = await userCollection.find({ username: username }).project({ username: 1, password: 1, _id: 1 }).toArray();

    console.log(result);

    res.send(`<h1>Hello ${username}</h1>`);
});

// The route for creating the user.
app.get('/signup', (req, res) => {
    res.render("signup");
});

// A POST method.
// req.body is created by "app.use(express.urlencoded({extended: false}));"
// now it can parse the information that user inputted from the above code
// which now the server side can manage with those data.
{/* <input name="username" …>
<input name="email" …>
<input name="password" …> */}
app.post('/signupSubmit', async (req, res) => {
    var username = req.body.username;
    var email = req.body.email;
    var password = req.body.password;
    var role = req.body.role;

    // Checkin the user input by following the condition below.
    const schema = Joi.object(
        {
            username: Joi.string().alphanum().max(20).required(),
            email: Joi.string().email().required(),
            password: Joi.string().max(20).required(),
            role: Joi.string().required()
        }
    );

    // Check if the input follows the condition of the schema(Joi)
    const validationResult = schema.validate({ username, email, password, role }, { abortEarly: false });

    if (validationResult.error != null) {
        // collect all missing/empty field names
        const fields = validationResult.error.details.map(d => d.context.key);
        const unique = Array.from(new Set(fields));

        // build "X is required." for each
        const msgs = unique
            .map(f => `${f} is required.`)
            .join(' ');

        // res.send() sends the body(본문) to the client directly.
        // The URL maintains.    
        res.send(`
            <p>${msgs}</p>
            <a href="/signup">Try again</a>
        `);
        return;
    }

    // To convert the simple text pw into bcrypt by using original pw and saltRounds.
    var hashedPassword = await bcrypt.hash(password, saltRounds);

    // Pushing a new "user" information to the array Asynchronously, therefore it waits until
    // it successfully stores the information in mongoDB.
    // Storing in the MongoDB 'users' database that we setted in line 47
    // so that the information is stored even though we turn off the server.
    await userCollection.insertOne({
        username: username,
        email: email,
        password: hashedPassword,
        role: role
    });

    // Storing session when user successfully signs up.
    req.session.authenticated = true;
    req.session.username = username;
    req.session.email = email;
    req.session.cookie.maxAge = expireTime;
    // Add role field in the session so when user wants to access /admin
    // it can fetch it from the session.
    req.session.role = role;


    console.log("Inserted user");

    // Changes the URL directly moving to the other route.
    res.redirect('/members');
});

// A funtion to check admin
// function adminAuthorization(req, res, next)
// {
//     if()
// }
// The route for admin page.
app.get('/admin', async (req, res) => {
    if (!req.session.authenticated) {
        return res.redirect("login");
    }
    else if (req.session.role === 'admin') {
        const users = await userCollection
            .find({})
            .project({ username: 1, role: 1, _id: 0 })
            .toArray();

        return res.render("admin", { users });
    }
    // If the user type is 'user' then they cannot access to admin page.
    // res.status(403);
    return res.status(403).render('forbidden', { message: 'You are not authorized to access this page.' });
});

app.post('/promote/:username', async (req, res) => {
    const username = req.params.username;
    await userCollection.updateOne({ username }, { $set: { role: 'admin' } });
    res.redirect('/admin');
})

app.post('/demote/:username', async (req, res) => {
    const username = req.params.username;
    await userCollection.updateOne({ username }, { $set: { role: 'user' } });
    res.redirect('/admin');
})

// The route for login page.
app.get('/login', (req, res) => {
    res.render("login");
});

// The route for logging in page which checks the matching 
// users with the corresponding pw.
app.post('/loginSubmit', async (req, res) => {
    var email = req.body.email;
    var password = req.body.password;

    const schema = Joi.object(
        {
            email: Joi.string().email().required(),
            password: Joi.string().max(20).required()
        }
    );

    // Check
    const validationResult = schema.validate({ email, password }, { abortEarly: false });

    if (validationResult.error != null) {
        // collect all missing/empty field names
        const fields = validationResult.error.details.map(d => d.context.key);
        const unique = Array.from(new Set(fields));

        // build "X is required." for each
        const msgs = unique
            .map(f => `${f} is required.`)
            .join(' ');

        res.send(`
            <p>${msgs}</p>
            <a href="/login">Try again</a>
        `);
        return;
    }

    // Fetch the user info from the MongoDB (Probably fetching only 1)
    const result = await userCollection.find({ email: email })
        .project({ email: 1, password: 1, role: 1, username: 1, _id: 1 }).toArray();

    // How the log in process works (comparing the username and the password)
    // Since it's like an array, if the length is not 1 this means that it didn't 
    // fetch any of it which is an error.
    // In this case, it means that there is no user with the given email and the password.
    if (result.length != 1) {
        console.log("user not found");
        res.render('error', { type: 1 });
        return;
    }
    // result[0] is the first index of an array which is the one fetched by the mongoDB.
    if (await bcrypt.compare(password, result[0].password)) {
        console.log("correct password");

        // This 3 lines of code is storing the data in the session so that
        // it can remember the user when they reaccess with the same session (browser).
        // Saving the username as well from the mongoDB so that it can show it in the root page.
        req.session.authenticated = true;
        req.session.email = email;
        req.session.username = result[0].username;
        req.session.cookie.maxAge = expireTime;
        req.session.role = result[0].role;

        res.redirect('/members');
        return;
    }
    else {
        // When the email exists in the database but it does not matches the password.
        console.log("incorrect password");
        res.render('error', { type: 2 });
        return;
    }
});

// The route when the user successfully logs in.
app.get('/loggedin', (req, res) => {
    // If you don't have the cookie, it redirects to the login page.
    if (!req.session.authenticated) {
        res.redirect('/login');
    }

    var html = `
    You are logged in!
    `;
    res.send(html);
});



// The route for log out page.
app.get('/logout', (req, res) => {
    // Basically deleting the session so it cannot access again
    req.session.destroy();

    res.redirect('/');
});

// The route for members page.
app.get('/members', (req, res) => {

    if (!req.session.authenticated) {
        return res.redirect('/');
    }

    const username = req.session.username;

    // Array of images
    const images = ['cat1.jpg', 'cat2.jpg', 'cat3.jpg'];

    res.render("members", { username: username, images: images });
});

// 404 Page, must be placed at the end of all the routes.
// but before "app.listen".
app.get("*", (req, res) => {
    res.render('404');
});

// Start the server
app.listen(port, () => {
    console.log(`Server is runninig on http://localhost:${port}`);
});