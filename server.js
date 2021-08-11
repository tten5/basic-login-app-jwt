/* Program: Server for simple login website
            using jwt, mongodb 
            and can let user change password 
 */

// import modules 
const express = require('express');
const path = require("path");
const mongoose = require('mongoose')
const User = require('./models/user')
const bcrypt = require('bcryptjs') // for hashing the password
const jwt = require('jsonwebtoken')
require('dotenv').config();

// take variable from .env file
const {API_PORT, MONGO_URL} = process.env;
// connect to mongodb

mongoose.connect(process.env.MONGO_URL, {
	useNewUrlParser: true,
	useUnifiedTopology: true,
	useCreateIndex: true
}).then(() => {
    console.log("CONNECTION TO DATABASE OPEN!!!")
}).catch(err => {
    console.log("DB CONNECTION ERROR!!!")
    console.log(err)
    process.exit(1)
})

// declare variable
const app = express()
const port = process.env.PORT || API_PORT

// views setup
app.set('views', path.join(__dirname, 'views'))
app.set('view engine', 'ejs');

// other setup
app.use(express.json()) // give json representation of the body

// middleware to handle get request 
app.get('/', (req, res) => {
    res.render('index')
})

app.get('/login', (req, res) => {
    res.render('login')
})

app.get('/change-password', (req, res) => {
    res.render('change-password')
})


// handle post request from the register form
app.post('/api/register', async (req, res) => {
   
    const {username, password : plainTextPassword} = req.body

    // Validate username and password format
    if(!username || typeof username !== 'string') {
        return res.json({status : 'error', error: 'Invalid username'})
    }

    if(!plainTextPassword || typeof plainTextPassword !== 'string') {
        return res.json({status : 'error', error: 'Invalid password'})
    }

    if(plainTextPassword.length < 5) {
        return res.json({status : 'error', error: 'Password too short. Should be longer than 4 characters'})
    }

    // hashing plainTextPassword
    const password = await bcrypt.hash(plainTextPassword, 10)
    
    try {
        const userInfo = await User.create({
            username,
            password
        })
        console.log("User created successfully", userInfo)
    } catch (error) {
        console.log(JSON.stringify(error))
        if (error.code === 11000) {
            // 11000 is for duplicated key
            return res.json({status: 'error', error : 'Username already exist. Please login' })
        }
        throw error
    }
    
    // if data from form is ok, denote the status as ok
    res.json({ status: 'ok'}) // will automatically set up headers and everything come with the POST request
})


// handle post request from the login form
app.post('/api/login', async (req, res) => {
    const {username, password} = req.body
    
    // find any user that has username match 
    const user = await User.findOne({username}).lean()
    console.log("User logged in successfully", user)
    
    // check whether the user exists
    if(!user) {
        return res.json({status : 'error', error: 'Invalid username/password'})
    }

    // check whether the password from request can be one of the possibilities of the password stored in db
    if(await bcrypt.compare(password, user.password)) {
        // the username, password combination is success
        // generate a token and response the token to client
        const token = jwt.sign({ 
            id: user._id,
            username: user.username 
        }, process.env.TOKEN_KEY)
        
        return res.json({status : 'ok', data : token})

    }

    // if the password is not correct
    res.json({status : 'error', error: 'Invalid username/password'})
})

app.listen(port, () => {
    console.log(`Server up at port ${port}`);
})

