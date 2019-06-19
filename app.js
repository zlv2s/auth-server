const express = require('express')
const DB = require('./db')
const config = require('./config')
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')
const bodyParser = require('body-parser')

const db = new DB('sqlitedb')
const app = express()
const router = express.Router()

router.use(bodyParser.urlencoded({ extended: false }))
router.use(bodyParser.json())

// CORS middleware
const allowCrossDomain = function (req, res, next) {
  res.header('Access-Control-Allow-Origin', '*')
  res.header('Access-Control-Allow-Methods', '*')
  res.header('Access-Control-Allow-Headers', '*')
  next()
}

app.use(allowCrossDomain)

// router management
router.get('/', (req, res) => {
  res.status(200).send('Hello There !')
})

router.get('/all', (req, res) => {
  db.selectAll((err, users) => {
    if (err) return res.status(500).send('Server error')
    res.status(200).send({ users })
  })
})

router.post('/delete', (req, res) => {
  db.deleteById(req.body.id, err => {
    if (err) res.status(500).send(err)
    res.status(200).send('successfully deleted')
  })
})

router.post('/register', (req, res) => {
  db.insert([
    req.body.name,
    req.body.email,
    bcrypt.hashSync(req.body.password, 8),
    req.body.isAdmin
  ], err => {
    if (err) return res.status(500).send(err)

    db.selectByEmail(req.body.email, (err, user) => {
      if (err) return res.status(500).send('There was a problem getting user')

      let token = jwt.sign({ id: user.id }, config.secret, { expiresIn: 86400 })

      res.status(200).send({ auth: true, token, user })
    })
  })
})

router.post('/register-admin', (req, res) => {
  db.insert([
    req.body.name,
    req.body.email,
    bcrypt.hashSync(req.body.password, 8),
    req.body.isAdmin
  ], err => {
    if (err) return res.status(500).send('There was a problem registering the user')

    db.selectByEmail(req.body.email, (err, user) => {
      if (err) return res.status(500).send('There was a problem getting user')

      let token = jwt.sign({ id: user.id }, config.secret, { expiresIn: 86400 })

      res.status(200).send({ auth: true, token, user })
    })
  })
})

router.post('/login', (req, res) => {
  db.selectByEmail(req.body.email, (err, user) => {
    if (err) return res.status(500).send('Server error')

    if (!user) return res.status(404).send('User not exists')

    let passwordIsValid = bcrypt.compareSync(req.body.password, user.user_pass)

    if (!passwordIsValid) return res.status(401).send({ auth: false, token: null })

    let token = jwt.sign({ id: user.id }, config.secret, { expiresIn: 86400 })

    res.status(200).send({ auth: true, token, user })
  })
})

app.use(router)

let port = process.env.PORT || 3000

app.listen(port, () => {
  console.log('App listening on port:' + port)
})