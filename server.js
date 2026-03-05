// Module imports
require('dotenv').config()
const express = require('express')
const app = express()
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')

// The greater the number, the harder the password is to crack
const saltRounds = 10
const testHash = "$2b$10$ELk3buSmKcoD/hczYeDSt.bkZ2U6aOEXTII0w3rH4rL5HcOVUjKDG"

// Lets us send json with express
app.use(express.json())

// Landing Page
app.get('/', (req, res) => {
    return res.send('<h1>Hello World</h1>')
})

// Takes username and password, hashes password and returns username + hash for testing
app.post('/signup', (req, res) => {
    const username = req.body.username
    const password = req.body.password

    // bcrypt module hash function
    bcrypt.hash(password, saltRounds, function(err, hash) {
        if (err) return res.sendStatus(500)
        // STORE IN DB IN PROD, NEVER STORE PLAIN TEXT PASSWORDS 
        res.json({username, hash})
    })
})

// Takes username and password, compares password to hash in db
// serializes user into payload to sign jwt, returns token
app.post('/login', (req, res) => {
    const username = req.body.username
    const password = req.body.password

    const user = {name : username}

    // COMPARE PASSWORD TO THE HASH FROM DB 
    // TODO: Compare req.password to hash in db with bcrypt.compare
    //       If match == True, issue access Token and return it 
    //       Need to inject ACCESS_TOKEN_SECRET from .env

    // async functions runs at an unknown amount of time
    async function comparePassword(user, password) {
        // await - rest of code does not run until bcrypt is done
        const match = await bcrypt.compare(password, testHash)

        if (match) {
            const accessToken = generateAccessToken(user)

            // short-lived token to get more access tokens????
            const refreshToken = jwt.sign(user, process.env.REFRESH_TOKEN_SECRET)

            return res.json({accessToken : accessToken, refreshToken : refreshToken})
        }

        return res.sendStatus(403)
    }

    return comparePassword(user, password)
})

app.post('/token', (req,res) => {
    const refreshToken = req.body.accessToken

    if (refreshToken === null) return res.sendStatus(401)

    jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET, (err, user) => {
        if (err) return res.status(403).send('Failed to verify')
        const accessToken = generateAccessToken({name : user.name})
        res.json({accessToken : accessToken})
    })
})

app.listen(8980, (error) => {
    if (error) return console.log(`Server failed to start ${error}`)
    console.log("Server is listening")
})

function generateAccessToken(user) {
    return jwt.sign(user, process.env.ACCESS_TOKEN_SECRET, {expiresIn : '5m'})
}