'use strict'
const express = require('express')
const cors = require('cors')
const bodyParser = require('body-parser')
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')

let app = express()
app.use(cors())
app.use(bodyParser.json())

// TODO: obviosly move these to environment files before deployment
const savedHash = '$2b$10$IZDfFKIjiQUD5Pdj.Dk84OESZszXtLhx.JhCYVbeDIgTeTQ1QgzDm' // < test
const SECRET = 'IZDfF7723r4KIjiQUD09asjn9sg.css87oafg09sOESZszXtLhx'

let blacklist = {}

const failedLogins = {}

let requestingIP

// blacklist check
app.use((req, res, next) => {
  requestingIP = req.headers['x-forwarded-for'] || req.connection.remoteAddress;
  if (!!blacklist[requestingIP]) {
    // ip has been blacklisted, fail back
    return res.sendStatus(403)
  }
  next()
})
// add to blacklist after too many failed logins
app.use((req, res, next) => {
  if (failedLogins[requestingIP] === undefined) {
    failedLogins[requestingIP] = {
      firstAttempt: new Date().getTime(),
      attempts: 1
    }
  } else {
    failedLogins[requestingIP].attempts++
    // check for too many attempts
    if (failedLogins[requestingIP].attempts > 2) {
      blacklist[requestingIP] = new Date().getTime()
    }
  }
  next()
})

app.post('/', (req, res) => {
  try {
    const { accessCode, userName } = req.body.credentials

    bcrypt.compare(accessCode, savedHash, (err, match) => {
      if (err) {
        console.log('HASHING COMPARE HAS FAILED')
        throw new Error(err)
      } 

      if (!match) {
        console.log('-INVALID CODE PROVIDED')
        return res.sendStatus(401)
      }

      // app.get('/', (req, res) => {
      //   const ip = req.headers['x-forwarded-for'] || req.connection.remoteAddress;
      //   console.log('>> Check')
      //   console.log(ip)
      //   res.send('looking good ;)')
      // })

      const accessToken = jwt.sign({ userName }, SECRET)

      res.status(200).json({
        accessToken
      })

      console.log(userName)
    })
  } catch(e) {
    
    throw new Error(e)
  }
})

app.listen(3000, () => {
  console.log('application running on port 3000')
})

