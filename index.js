const express = require("express");
const _ = require("lodash");
const axios = require("axios");
const fetch = require("node-fetch");
const jwt = require("jsonwebtoken");
const marked = require("marked");
const moment = require("moment");
require("dotenv").config();

const app = express();
app.use(express.json());

// --- Route basique ---
app.get("/", (req, res) => {
  res.json({ message: "Dependabot test app", date: moment().format("LLLL") });
});

// --- Lodash (4.17.4 → vulnérable prototype pollution CVE-2019-10744) ---
app.get("/merge", (req, res) => {
  const base = { role: "user" };
  const override = req.query;
  const merged = _.merge({}, base, override);
  res.json(merged);
});

// --- marked (1.2.9 → XSS CVE-2022-21681) ---
app.get("/render", (req, res) => {
  const md = req.query.text || "# Hello World";
  res.send(marked(md));
});

// --- jsonwebtoken (8.5.1 → CVE-2022-23529) ---
app.post("/login", (req, res) => {
  const { username } = req.body;
  const token = jwt.sign({ username }, process.env.JWT_SECRET || "secret", {
    expiresIn: "1h",
  });
  res.json({ token });
});

app.get("/verify", (req, res) => {
  const token = req.headers.authorization?.split(" ")[1];
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET || "secret");
    res.json({ valid: true, decoded });
  } catch {
    res.status(401).json({ valid: false });
  }
});

// --- axios (0.21.1 → SSRF CVE-2021-3749) ---
app.get("/proxy", async (req, res) => {
  const { url } = req.query;
  try {
    const response = await axios.get(url);
    res.json(response.data);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// --- node-fetch (2.6.1 → CVE-2022-0235) ---
app.get("/fetch", async (req, res) => {
  const { url } = req.query;
  try {
    const response = await fetch(url);
    const data = await response.json();
    res.json(data);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
