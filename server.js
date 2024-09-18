const express = require("express");
const mongoose = require("mongoose");
const User = require("./model/User");
const bcryptjs = require("bcryptjs");
const jwt = require("jsonwebtoken");
const app = express();
app.use(express.json());

const SECRET_KEY = "engineercodewala123";

// Database connection (consider moving credentials to environment variables)
mongoose
  .connect("ur_mongodb_url")
  .then(() => {
    console.log("Database connected");
  })
  .catch((err) => {
    console.log("Database connection failed", err);
  });

// Register API
app.post("/register", async (req, res) => {
  const { username, password } = req.body;

  try {
    const existingUser = await User.findOne({ username });
    if (existingUser) {
      return res.status(200).json({ message: "User already exists" });
    }

    const hashedPassword = await bcryptjs.hash(password, 10);
    const newUser = new User({ username, password: hashedPassword });
    await newUser.save();

    return res
      .status(201)
      .json({ message: "User created successfully", data: newUser });
  } catch (error) {
    return res
      .status(500)
      .json({ message: "Internal server error", error: error.message });
  }
});

// Login API
app.post("/login", async (req, res) => {
  const { username, password } = req.body;

  try {
    const existingUser = await User.findOne({ username });
    if (!existingUser) {
      return res.status(404).json({ message: "User not found" });
    }

    const isValidPassword = await bcryptjs.compare(
      password,
      existingUser.password
    );
    if (!isValidPassword) {
      return res.status(400).json({ message: "Password not matched" });
    }

    const token = jwt.sign({ username: existingUser.username }, SECRET_KEY, {
      expiresIn: "1h",
    });
    return res.status(200).json({
      message: "User logged in successfully",
      data: existingUser,
      token: token,
    });
  } catch (error) {
    return res
      .status(500)
      .json({ message: "Internal server error", error: error.message });
  }
});

// Verify Token API
const getRemainingTime = (expTime) => {
  const currentTime = Math.floor(Date.now() / 1000);
  return Math.max(0, Math.floor((expTime - currentTime) / 60)); // Remaining time in minutes
};

app.post("/verifyToken", async (req, res) => {
  const { token } = req.body;

  if (!token) {
    return res.status(400).json({ message: "Token missing" });
  }

  jwt.verify(token, SECRET_KEY, (error, decoded) => {
    if (error) {
      return res.status(201).json({ message: "Token expired or invalid" });
    }

    const remainingTime = getRemainingTime(decoded.exp);
    return res.status(200).json({
      message: "Token is valid",
      data: {
        username: decoded.username,
        remainingTime,
      },
    });
  });
});

// Authenticate middleware
const authenticateUser = (req, res, next) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (!token) {
    return res
      .status(400)
      .json({ message: "Access denied. No token provided." });
  }

  jwt.verify(token, SECRET_KEY, (error, user) => {
    if (error) {
      return res.status(201).json({ message: "Invalid token" });
    }
    req.user = user;
    next();
  });
};

// Get user details route
app.get("/details", authenticateUser, async (req, res) => {
  try {
    const user = await User.findOne({ username: req.user.username });
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }
    return res.status(200).json({ data: user });
  } catch (error) {
    return res
      .status(500)
      .json({ message: "Internal server error", error: error.message });
  }
});

// Server listening on port 3300
app.listen(3300, () => {
  console.log("Server running on PORT 3300");
});
