
const express = require("express")
const mongoose = require("mongoose")
const cors = require("cors")
const jwt = require("jsonwebtoken")
const bcrypt = require("bcryptjs")

require("dotenv").config()

const app = express()

// Middleware
app.use(cors())
app.use(express.json())

// Error Handler Middleware
const errorHandler = (err, req, res, next) => {
  console.error(err.stack)

  if (err.name === "ValidationError") {
    return res.status(400).json({
      error: "Validation Error",
      details: Object.values(err.errors).map((e) => e.message),
    })
  }

  if (err.name === "JsonWebTokenError") {
    return res.status(401).json({ error: "Invalid token" })
  }

  res.status(500).json({ error: "Something went wrong!" })
}

// MongoDB Connection with better error handling
mongoose
  .connect(process.env.MONGODB_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  })
  .then(() => console.log("Connected to MongoDB"))
  .catch((err) => {
    console.error("MongoDB connection error:", err)
    process.exit(1)
  })

// Enhanced User Schema with validation
const userSchema = new mongoose.Schema({
  username: {
    type: String,
    required: [true, "Username is required"],
    unique: true,
    trim: true,
    minlength: [3, "Username must be at least 3 characters long"],
  },
  password: {
    type: String,
    required: [true, "Password is required"],
    minlength: [6, "Password must be at least 6 characters long"],
  },
  createdAt: {
    type: Date,
    default: Date.now,
  },
})

// Enhanced Post Schema with validation
const postSchema = new mongoose.Schema({
  title: {
    type: String,
    required: [true, "Title is required"],
    trim: true,
    minlength: [3, "Title must be at least 3 characters long"],
    maxlength: [100, "Title cannot exceed 100 characters"],
  },
  content: {
    type: String,
    required: [true, "Content is required"],
    minlength: [10, "Content must be at least 10 characters long"],
  },
  category: {
    type: String,
    required: [true, "Category is required"],
    enum: ["Technology", "Programming", "Design", "Career", "Other"],
  },
  authorId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "User",
    required: true,
  },
  author: {
    type: String,
    required: true,
  },
  createdAt: {
    type: Date,
    default: Date.now,
  },
  updatedAt: {
    type: Date,
    default: Date.now,
  },
})

const User = mongoose.model("User", userSchema)
const Post = mongoose.model("Post", postSchema)

// Authentication Middleware with better error handling
const auth = async (req, res, next) => {
  try {
    const token = req.header("Authorization")?.replace("Bearer ", "")

    if (!token) {
      throw new Error("No authentication token provided")
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET)
    const user = await User.findById(decoded.userId)

    if (!user) {
      throw new Error("User not found")
    }

    req.user = user
    next()
  } catch (error) {
    res.status(401).json({ error: "Please authenticate properly" })
  }
}

// Enhanced Routes with better error handling and validation

// Register Route
app.post("/api/register", async (req, res, next) => {
  try {
    const { username, password } = req.body

    // Check if user already exists
    const existingUser = await User.findOne({ username })
    if (existingUser) {
      return res.status(400).json({ error: "Username already exists" })
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10)

    // Create user
    const user = new User({ username, password: hashedPassword })
    await user.save()

    // Generate token
    const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET)

    res.status(201).json({
      user: { id: user._id, username: user.username },
      token,
    })
  } catch (error) {
    next(error)
  }
})

// Login Route
app.post("/api/login", async (req, res, next) => {
  try {
    const { username, password } = req.body

    // Find user
    const user = await User.findOne({ username })
    if (!user) {
      return res.status(401).json({ error: "Invalid credentials" })
    }

    // Verify password
    const isValidPassword = await bcrypt.compare(password, user.password)
    if (!isValidPassword) {
      return res.status(401).json({ error: "Invalid credentials" })
    }

    // Generate token
    const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET)

    res.json({
      user: { id: user._id, username: user.username },
      token,
    })
  } catch (error) {
    next(error)
  }
})

// Get Posts Route
app.get("/api/posts", async (req, res, next) => {
  try {
    const { category, search } = req.query
    const query = {}

    // Filter by category if provided
    if (category) {
      query.category = category
    }

    // Search in title and content if search term provided
    if (search) {
      query.$or = [{ title: { $regex: search, $options: "i" } }, { content: { $regex: search, $options: "i" } }]
    }

    const posts = await Post.find(query).sort({ createdAt: -1 }).limit(20)

    res.json(posts)
  } catch (error) {
    next(error)
  }
})

// Create Post Route
app.post("/api/posts", auth, async (req, res, next) => {
  try {
    const post = new Post({
      ...req.body,
      authorId: req.user._id,
      author: req.user.username,
    })

    await post.save()
    res.status(201).json(post)
  } catch (error) {
    next(error)
  }
})

// Update Post Route
app.put("/api/posts/:id", auth, async (req, res, next) => {
  try {
    const updates = {
      ...req.body,
      updatedAt: Date.now(),
    }

    const post = await Post.findOneAndUpdate({ _id: req.params.id, authorId: req.user._id }, updates, {
      new: true,
      runValidators: true,
    })

    if (!post) {
      return res.status(404).json({ error: "Post not found or unauthorized" })
    }

    res.json(post)
  } catch (error) {
    next(error)
  }
})

// Delete Post Route
app.delete("/api/posts/:id", auth, async (req, res, next) => {
  try {
    const post = await Post.findOneAndDelete({
      _id: req.params.id,
      authorId: req.user._id,
    })

    if (!post) {
      return res.status(404).json({ error: "Post not found or unauthorized" })
    }

    res.json({ message: "Post deleted successfully" })
  } catch (error) {
    next(error)
  }
})

// Get Single Post Route
app.get("/api/posts/:id", async (req, res, next) => {
  try {
    const post = await Post.findById(req.params.id)

    if (!post) {
      return res.status(404).json({ error: "Post not found" })
    }

    res.json(post)
  } catch (error) {
    next(error)
  }
})

// Token Verification Route
app.get("/api/verify", auth, async (req, res) => {
  res.json({ user: { id: req.user._id, username: req.user.username } })
})


app.use(errorHandler)

const PORT = process.env.PORT || 5000
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`)
})

