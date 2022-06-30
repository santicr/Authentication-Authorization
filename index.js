const express = require('express')
const mongoose =  require('mongoose')
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')
const {expressjwt : expressJwt} = require('express-jwt')
const User = require('./user')

mongoose.connect('mongodb+srv://admin:admin@cluster0.lslkadu.mongodb.net/auth?retryWrites=true&w=majority')

const app = express()

app.use(express.json())

const validateJwt = expressJwt({ secret:'mi-string-secreto', algorithms: ['HS256']})

const signToken = _id => jwt.sign({ _id }, 'mi-string-secreto')

app.post('/register', async (req, res) => {
    const { body } = req
    console.log({body})
    try {
        const isUser = await User.findOne({ email: body.email })
        if(isUser) {
            return res.status(403).send('Usuario ya registrado')
        }
        const salt = await bcrypt.genSalt()
        const hashed = await bcrypt.hash(body.password, salt)
        const user = await User.create({email: body.email, password: hashed, salt})
        const sign = signToken(user._id)
        
        res.status(201).send(sign)
    }
    catch(err) {
        console.log(err)
        res.status(500).send(err.message)
    }
})

app.post('/login', async (req, res) => {
    const { body } = req

    try {
        const user = await User.findOne({ email: body.email })
        if(!user){
            res.send('Usario y/o contraseña inválida')
        }
        else{
            const isMatch = await bcrypt.compare(body.password, user.password)
            if (isMatch){
                const signed = signToken(user._id)
                res.status(200).send(signed)
            }
            else {
                res.status(403).send('Usario y/o contraseña inválida')
            }
        }
    }
    catch(err){
        res.status(500).send(err.message)
    }
})

const findAAU = async (req, res, next) => {
    try {
        const user = await User.findById(req.user._id)
        if(!user){
            return res.status(401).end()   
        }
        req.user = user
        next()
    }
    catch (e){
        next(e)
    }
}

const isAuth = express.Router().use(validateJwt, findAAU)

app.get('/lala', isAuth, (req, res) => {
    throw new Error('Nuevo error')
    res.send(req.user)
})

app.use((err, req, res, next) => {
    console.log("Error mi nuevo error", err.stack)
    next(err)
})

app.listen(3000, () => {
    console.log("Listening in port 3000")
})