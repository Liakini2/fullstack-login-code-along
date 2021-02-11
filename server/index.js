require('dotenv').config();
const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const massive = require('massive');

const app = express();

app.use(express.json());

let { SERVER_PORT, CONNECTION_STRING, SESSION_SECRET } = process.env;

app.use(
  session({
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: true,
    //milliseconds measurement for a week (milliseconds, seconds, minutes, hours, days)
    cookie: {maxAge: 1000 * 60 * 60 * 24 * 7}
  })
);

massive({
  connectionString: CONNECTION_STRING,
  ssl: {rejectUnauthorized:false}
}).then(db => {
  app.set('db', db);
  console.log('db connected')
}).catch(err=> console.log(err));

//async and await take the place of .then and .catch
//but they do the same thing
//declare async before (req, res)
//set db.function to a variable with await prior to the function
//This just forces it to resolve itself one step at a time instead of running everything at the same time
//all requests to db are returned as an array

app.post('/auth/signup', async (req, res) =>{
  //req.body is what is coming from the user
  const {email,password} = req.body
  let db = req.app.get('db')
  //this takes in the email as an argument
  const user = await db.check_user_exists(email)
  //this applies if email already exists
  //there is only 1 item in our array the email
  if (user[0]){
    return res.status(401).send('User already exists')
  } 
  //otherwise we are going to hash the password
  let salt = bcrypt.genSaltSync(10)
  //passord passed in is from req.body and saved as hash with salt
  let hash = bcrypt.hashSync(password, salt)
  //now we create a user
  //we put has in the place of password NEVER SEND PASSWORD HERE
  let createdUser = await db.create_user([email, hash])
  //store your data to a session as an object
  req.session.user = {id: createdUser[0].id, email: createdUser[0].email}
  //send over the session as a result
  res.status(200).send(req.session.user)
})

// app.post('/auth/signup', async (req, res) => {
//   const { email, password } = req.body;
//   let db = req.app.get('db');
//   const user = await db.check_user_exists(email)
//   if (user[0]){
//     return res.status(401).send('User already exists');
//   }
//   let salt = bcrypt.genSaltSync(10);
//   let hash = bcrypt.hashSync(password, salt);
//   let [createdUser] = await db.create_user([email, hash])
//   req.session.user = { id: createdUser.id, email: createdUser.email}
//   res.status(200).send(req.session.user)
// })

app.post ('/auth/login', async (req, res) =>{
  const {email, password} = req.body
  let db = req.app.get('db')
  let foundUser = await db.check_user_exists(email)
  if (!foundUser[0]){
    return res.status(401).send('Incorrect email!')
  }
  let authenticated = bcrypt.compareSync(password, foundUser.user_password)
  if(authenticated){
    req.session.user = {
      id: foundUser.id,
      email: foundUser.email
    }
    res.status(200).send(req.session.user)
  } else {
    return res.status(401).send('Incorrect password!')
  }
})

//would need to add function to front end to send user to the home/login screen
app.get('/auth/login', (req, res) =>{
  req.session.destroy()
  res.sendStatus(200)
})

app.get('/auth/user', (req, res)=>{
  if (req.session.user){
    res.status(200).send(req.session.user)
  } else {
    res.status(401).send(`Please Log In`)
  }
})



app.listen(SERVER_PORT, () => {
  console.log(`Listening on port: ${SERVER_PORT}`);
});
