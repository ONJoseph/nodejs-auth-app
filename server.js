const express = require('express');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');

const app = express();
const port = process.env.PORT || 3000;

app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());

// In-memory database for user storage
const users = [];

// Register a new user
app.post('/register', async (req, res) => {
  const { username, password } = req.body;

  // Check if the username already exists
  if (users.find((user) => user.username === username)) {
    return res.status(400).json({ error: 'Username already exists' });
  }

  // Hash the password before storing it
  const hashedPassword = await bcrypt.hash(password, 10);

  const newUser = {
    username,
    password: hashedPassword,
  };

  users.push(newUser);

  res.status(201).json({ message: 'User registered successfully' });
});

// Login and check credentials
app.post('/login', async (req, res) => {
  const { username, password } = req.body;

  // Find the user by username
  const user = users.find((user) => user.username === username);

  if (!user) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  // Compare the provided password with the hashed password
  const passwordMatch = await bcrypt.compare(password, user.password);

  if (!passwordMatch) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  res.status(200).json({ message: 'Login successful' });
});

app.listen(port, () => {
  console.log(`Server is running on http://localhost:${port}`);
});

/*
Node.js application that uses the Express.js framework to implement user registration and login functionality with password hashing. Here's a detailed explanation of the code:

Import Required Modules:

express: Imports the Express.js framework for building web applications.
body-parser: Imports the body-parser middleware for parsing HTTP request bodies.
bcrypt: Imports the bcrypt library for securely hashing and verifying passwords.
Create an Express Application and Set Port:

Creates an instance of the Express application and assigns it to the app variable.
Defines a port number for the server, either using the environment variable process.env.PORT or falling back to port 3000.
Configure Middleware:

Configures body-parser to handle URL-encoded and JSON request bodies. This middleware is used to parse incoming POST request data.
In-Memory Database:

Initializes an in-memory array users to store user data. This array simulates a simple user database for demonstration purposes.
Register a New User (/register POST Endpoint):

Defines a POST route at the '/register' URL path.
Parses the username and password from the request body.
Checks if a user with the same username already exists in the users array. If a duplicate is found, it returns a 400 Bad Request response with an error message.
Hashes the provided password using bcrypt with a cost factor of 10 to generate a secure hash.
Creates a new user object with the username and hashed password.
Pushes the new user object into the users array.
Responds with a 201 Created status and a success message indicating that the user was registered.
Login and Check Credentials (/login POST Endpoint):

Defines a POST route at the '/login' URL path.
Parses the username and password from the request body.
Searches for a user with the specified username in the users array.
If no user is found, it returns a 401 Unauthorized response with an error message indicating invalid credentials.
If a user is found, it compares the provided plaintext password with the stored hashed password using bcrypt.compare().
If the passwords match, it responds with a 200 OK status and a success message indicating that the login was successful.
If the passwords do not match, it returns a 401 Unauthorized response with an error message indicating invalid credentials.
Start the Server:

Listens on the defined port (either from the environment variable or port 3000).
Outputs a message to the console indicating that the server is running.
In summary, this code sets up a basic Express.js server that allows users to register by providing a username and password. User passwords are securely hashed before being stored. Users can also log in by providing their credentials, and the server validates the login based on the stored hashed password. This code is for educational purposes and does not include a persistent database for user storage.
*/