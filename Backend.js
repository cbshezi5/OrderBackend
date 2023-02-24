const express = require('express');
const app = express();
const sql = require('mssql');
const jwt = require('jsonwebtoken');
const io = require('socket.io')();
const cors = require('cors');
const path = require('path');
const bcrypt = require('bcryptjs');
const bodyParser = require('body-parser')
require('dotenv').config()
const saltRounds = 10;


// Connect to MSSQL server
const config = {
  user: process.env.DB_USERNAME,
  password: process.env.DB_PASSWORD,
  server: process.env.BD_HOSTNAME,
  database: process.env.DB_NAME,
  stream: false,
  port:1433,
  options: {
    trustedConnection: true,
    encrypt: false,
    enableArithAbort: true,
    trustServerCertificate: true,
  }
};
sql.connect(config)
  .then(pool => {
    if (pool.connected) {
      console.log('Connected to MSSQL server');
    }
  })
  .catch(err => console.error(err));

// Middleware for authenticating JWT token
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (token == null) return res.sendStatus(401);

  jwt.verify(token, process.env.SECRET_HASH_KEY, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
}

app.use(bodyParser.urlencoded({ extended: false }))

// parse application/json
app.use(bodyParser.json())

// Configure CORS to only allow requests from example.com
app.use(cors({
  origin: ['http://localhost'],


}));

// Route for authenticating user and returning JWT token
app.post('/auth/', async (req, res) => {
    const username = req.body.username;
    const password = req.body.password;

    //Query the user using the username within the MSSQL server
    new sql.Request()
      .input('Username', sql.NVarChar(50), username)
      .query('SELECT * FROM users WHERE Username =  @Username')
      .then(async(result) => {
        let user = result.recordset[0];
      
        // Check if user exists and password is correct using hashing of data making sure the data
        // is not readable and brute force can't reach it's
        if (user && await bcrypt.compare(password, user.Password)) {
        // Issue JWT token
            const token = jwt.sign({ username: user.username }, process.env.SECRET_HASH_KEY);
            res.json({ token: token,usercontrolkey : user.PersonId,name:user.Firstname+" "+user.Lastname });
        } else {
            res.status(401).send({message:'Invalid username or password'});
        }
    });

});

app.get('/', function(req, res) {
  res.sendFile(path.join(__dirname, '/index.html'));
});
// Route for getting order data 
app.get('/order/:id', authenticateToken, (req, res) => {
  const PersonId = req.params.id;
  // Query the MSSQL server for the order data
  new sql.Request()
    .input('PersonId', sql.Int, PersonId)
    .query('SELECT * FROM orders WHERE PersonId = @PersonId')
    .then(result => {
      if (result.recordset.length === 0) {
        res.sendStatus(404);
      } else {
        res.json(result.recordset[0]);
      }
    })
    .catch(error => {
      console.error(error);
      res.sendStatus(500);
    });
});


//Administrator Context
app.get('/allusers', (req, res, next) => {
  // Query the MSSQL server for the users to fill the select element
  new sql.Request()
    .query('SELECT * FROM users')
    .then(result => {
      if (result.recordset.length === 0) {
        res.sendStatus(404);
      } else {
        res.send(result.recordset);
      }
    })
    .catch(error => {
      console.error(error);
      res.sendStatus(500);
    });
});

// Socket.IO event for updating the order stage
io.on('connection', (socket) => {
  socket.on('updateStage', (data) => {
    const PersonId = data.PersonId;
    const newStage = data.stage;

    // Update the stage in the database
    new sql.Request()
      .input('PersonId', sql.Int, PersonId)
      .input('newStage', sql.NVarChar(50), newStage)
      .query('UPDATE orders SET Stage = @newStage WHERE PersonId = @PersonId')
      .then(() => {
        // Emit the updatedStage event to all connected clients and send the new state of the stage to the client
        io.emit('orderstage', { stage: newStage,PersonId: PersonId });
      })
      .catch(error => {
        // Let's not send an error since we already have a stage stated by our get Method
        console.error(error);
      });
  });
});

// Start the server
const server = app.listen(process.env.PORT || 80, () => {
  console.log(`Server started on port ${process.env.PORT}`);
});

// Attach Socket.IO to the server
io.attach(server);