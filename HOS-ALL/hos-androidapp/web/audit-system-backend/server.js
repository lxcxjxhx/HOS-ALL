const express = require("express");
const { MongoClient, ObjectId } = require("mongodb");
const dotenv = require("dotenv");
const fs = require("fs").promises;

dotenv.config();

const app = express();
app.use(express.json());

const uri = "mongodb://user:user@60.205.156.76:27017/?authSource=admin";
const client = new MongoClient(uri);

async function connectDB() {
  try {
    await client.connect();
    console.log("Connected to MongoDB");
  } catch (error) {
    console.error("MongoDB connection error:", error);
    process.exit(1);
  }
}

connectDB();
const db = client.db("finalhomework");

// Root route
app.get("/", (req, res) => {
  res.json({ message: "Welcome to the audit-system-backend API" });
});

// 登录API
app.post("/api/login", async (req, res) => {
  const { username, password } = req.body;
  try {
    const users = JSON.parse(await fs.readFile("users.json", "utf8"));
    const user = users.find(
      (u) => u.username === username && u.password === password
    );
    if (!user) {
      return res
        .status(401)
        .json({ success: false, message: "Invalid credentials" });
    }
    res.json({ success: true, role: user.role, username });
  } catch (error) {
    console.error("Login error:", error);
    res.status(500).json({ error: "Login failed" });
  }
});

// 获取游记列表API
app.get("/api/diaries", async (req, res) => {
  const { status, username, title, content } = req.query;
  try {
    const users = JSON.parse(await fs.readFile("users.json", "utf8"));
    const user = users.find((u) => u.username === username);
    if (!user) {
      return res.status(401).json({ error: "Invalid user" });
    }
    const query = { isDeleted: false };
    if (status && status !== "all") query.status = status;
    if (title) query.title = { $regex: title, $options: "i" };
    if (content) query.content = { $regex: content, $options: "i" };
    const diaries = await db.collection("diary").find(query).toArray();
    res.json(diaries);
  } catch (error) {
    console.error("Fetch diaries error:", error);
    res.status(500).json({ error: "Failed to fetch diaries" });
  }
});

// 更新游记状态API
app.put("/api/diaries/:id", async (req, res) => {
  const { id } = req.params;
  const { status, rejectReason, username } = req.body;
  try {
    const users = JSON.parse(await fs.readFile("users.json", "utf8"));
    const user = users.find((u) => u.username === username);
    if (!user) {
      return res.status(401).json({ error: "Invalid user" });
    }
    if (status === "deleted" && user.role !== "admin") {
      return res.status(403).json({ error: "Only admins can delete diaries" });
    }
    if (status === "rejected" && !rejectReason) {
      return res.status(400).json({ error: "Reject reason is required" });
    }
    const updateData = { status, updatedAt: new Date() };
    if (rejectReason) updateData.rejectReason = rejectReason;
    if (status === "deleted") {
      updateData.isDeleted = true;
      updateData.status = "rejected";
    }

    const result = await db
      .collection("diary")
      .updateOne({ _id: new ObjectId(id) }, { $set: updateData });

    if (result.matchedCount === 0) {
      return res.status(404).json({ error: "Diary not found" });
    }
    res.json({ success: true });
  } catch (error) {
    console.error("Update diary error:", error);
    res.status(500).json({ error: "Failed to update diary" });
  }
});

// 获取文件列表API
app.get("/api/files", async (req, res) => {
  const { username } = req.query;
  try {
    const users = JSON.parse(await fs.readFile("users.json", "utf8"));
    const user = users.find((u) => u.username === username);
    if (!user) {
      return res.status(401).json({ error: "Invalid user" });
    }
    const files = await db.collection("file").find().toArray();
    res.json(files);
  } catch (error) {
    console.error("Fetch files error:", error);
    res.status(500).json({ error: "Failed to fetch files" });
  }
});

const PORT = process.env.PORT || 3001;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
