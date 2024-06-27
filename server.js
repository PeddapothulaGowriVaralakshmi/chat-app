const express = require('express')
const bodyParser = require('body-parser')
const bcrypt = require('bcryptjs')
const path = require('path')
const sqlite3 = require('sqlite3').verbose()
const http = require('http')
const WebSocket = require('ws')

const app = express()
const server = http.createServer(app)
const wss = new WebSocket.Server({server})

const PORT = process.env.PORT || 3000

app.use(bodyParser.json())
app.use(express.static(path.join(__dirname, 'public')))

const dbPath = path.join(__dirname, 'application.db')
const db = new sqlite3.Database(dbPath, err => {
  if (err) {
    console.error('Error connecting to SQLite database:', err.message)
  } else {
    console.log('Connected to SQLite database')
    db.run(`CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            password TEXT NOT NULL,
            email TEXT NOT NULL
        )`)
  }
})

app.post('/signup', (req, res) => {
  const {username, password, email} = req.body

  bcrypt.genSalt(10, (err, salt) => {
    if (err) {
      console.error('Error generating salt:', err)
      return res.status(500).json({message: 'Error registering user'})
    }
    bcrypt.hash(password, salt, (err, hash) => {
      if (err) {
        console.error('Error hashing password:', err)
        return res.status(500).json({message: 'Error registering user'})
      }
      const insertQuery = `INSERT INTO users (username, password, email) VALUES (?, ?, ?)`
      db.run(insertQuery, [username, hash, email], function (err) {
        if (err) {
          console.error('Error inserting user into database:', err.message)
          return res.status(500).json({message: 'Error registering user'})
        }
        console.log(`User ${username} registered successfully`)
        res.status(201).json({message: 'User registered successfully'})
      })
    })
  })
})

app.post('/login', (req, res) => {
  const {username, password} = req.body

  db.get(`SELECT * FROM users WHERE username = ?`, [username], (err, row) => {
    if (err) {
      console.error('Error querying database:', err.message)
      return res.status(500).json({message: 'Error retrieving user'})
    }
    if (!row) {
      return res.status(401).json({message: 'User not found'})
    }

    bcrypt.compare(password, row.password, (err, result) => {
      if (err || !result) {
        return res.status(401).json({message: 'Invalid credentials'})
      }
      res.status(200).json({message: 'Login successful'})
    })
  })
})

app.get('/home', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'home.html'))
})

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'login.html'))
})

app.get('/signup', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'signup.html'))
})

// WebSocket handling
wss.on('connection', ws => {
  console.log('New client connected')

  ws.on('message', message => {
    const messageData = JSON.parse(message)
    const timestamp = new Date().toLocaleTimeString()
    messageData.timestamp = timestamp

    // Broadcast message to all connected clients
    wss.clients.forEach(client => {
      if (client.readyState === WebSocket.OPEN) {
        client.send(JSON.stringify(messageData))
      }
    })
  })

  ws.on('close', () => {
    console.log('Client disconnected')
  })
})

server.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`)
})
