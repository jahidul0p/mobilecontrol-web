const express = require("express");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 3000;

// JSON request গ্রহণ করার জন্য
app.use(express.json());

// public folder থেকে website files serve করবে
app.use(express.static(path.join(__dirname, "public")));

// Health check
app.get("/api/health", (req, res) => {
  res.json({
    status: "ok",
    message: "MobileControl Pro server is running"
  });
});

// Website
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "index.html"));
});

// Server start
app.listen(PORT, "0.0.0.0", () => {
  console.log(`Server running on port ${PORT}`);
});
