// Module imports
require('dotenv').config()
const express = require('express')
const app = express()
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')
const {initializeDb} = require('./database/client')

// The greater the number, the harder the password is to crack
const saltRounds = 10
const testHash = "$2b$10$OtEH1tqzkbyS9BEyIYKkReISfglfIm1LoirYnKBg.2zFaWffLFYlG"

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

let refreshTokens = []

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
            // store 
            refreshTokens.push(refreshToken)
            return res.json({accessToken : accessToken, refreshToken : refreshToken})
        }

        return res.sendStatus(403)
    }

    return comparePassword(user, password)
})

// passes back a fresh token to keep server alive
app.post('/token', (req,res) => {
    const refreshToken = req.body.token

    if (refreshToken === null) return res.sendStatus(401)

    if(!refreshTokens.includes(refreshToken)) return res.sendStatus(403)

    jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET, (err, user) => {
        if (err) return res.status(403).send('Failed to verify')
        const accessToken = generateAccessToken({name : user.name})
        res.json({accessToken : accessToken})
    })
})

posts = [
    {
        username: "Bob",
        likes: 10
    },
    {
        username: "John",
        likes: 20
    },
    {
        username: "Alex",
        likes: 1000
    }
]

app.get('/post', authenticateToken, (req, res) => {
    res.json(posts.filter(post => post.username === req.user.name))
})

app.listen(8980, (error) => {
    if (error) return console.log(`Server failed to start ${error}`)
    console.log("Server is listening")
    initializeDb()
})

function generateAccessToken(user) {
    return jwt.sign(user, process.env.ACCESS_TOKEN_SECRET, {expiresIn : '5m'})
}

app.delete('/logout', (req, res) => {
    refreshTokens = refreshTokens.filter(token => token !== req.body.token)
    res.sendStatus(204)
})

function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization']
    const token = authHeader && authHeader.split(" ")[1]

    if (token === null) return res.sendStatus(401)

    jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, user) => {
        if (err) return res.sendStatus(403)
            req.user = user
        next()
    })
}

// refresh token : eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoiQm9iIiwiaWF0IjoxNzc1MDg4MzEyfQ.KHapLIyKDRO2UlbffmjiCUFMy7FREdX_98s5NyVFgZo