const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");

const app = express();
app.use(express.json());
app.use(cors());

// 🔹 Connect to MongoDB
mongoose.connect("mongodb://127.0.0.1:27017/dashboardDB", {
    useNewUrlParser: true,
    useUnifiedTopology: true,
}).then(() => console.log("✅ MongoDB Connected"))
  .catch(err => console.log("❌ MongoDB Connection Error:", err));

// 🔹 Define Test Schema
const testSchema = new mongoose.Schema({
    title: String,
    content: String
});

const Test = mongoose.model("Test", testSchema);

// 🔹 Get all tests (for students)
app.get("/tests", async (req, res) => {
    const tests = await Test.find();
    res.json(tests);
});

// 🔹 Upload a test (for teachers)
app.post("/upload", async (req, res) => {
    const { title, content } = req.body;
    const newTest = new Test({ title, content });
    await newTest.save();
    res.send("✅ Test Uploaded!");
});

// 🔹 Start Server
const PORT = 5000;
app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
