const http = require('http');
const fs = require('fs');
const path = require('path');

// XSS - innerHTML
function renderComment(comment) {
    document.getElementById('comments').innerHTML = comment;
}

// XSS - document.write
function showMessage(msg) {
    document.write(msg);
}

// Eval injection
function calculate(expression) {
    return eval(expression);
}

// Eval via Function constructor
function runCode(code) {
    const fn = new Function(code);
    return fn();
}

// setTimeout with string (eval-like)
function delayed(code) {
    setTimeout("alert('hello')", 1000);
}

// Prototype pollution
function merge(target, source) {
    for (const key in source) {
        target[key] = source[key];
    }
}

// Hardcoded secrets
const API_KEY = "sk-1234567890abcdef1234567890abcdef";
const password = "SuperSecretPassword123";

// Insecure random
function generateId() {
    return Math.random().toString(36);
}

// Path traversal
function readUserFile(req, res) {
    const filePath = path.join('/uploads', req.query.filename);
    fs.readFile(filePath, (err, data) => {
        res.send(data);
    });
}

// SSRF
function proxyRequest(req, res) {
    fetch(req.query.url).then(response => {
        res.send(response);
    });
}

// NoSQL injection
async function findUser(req, res) {
    const user = await db.collection('users').findOne({ username: req.body.username });
    res.json(user);
}

// Insecure deserialization
const serialize = require('node-serialize');
function processData(req, res) {
    const obj = serialize.unserialize(req.body.data);
    res.json(obj);
}

// dangerouslySetInnerHTML (React)
function Comment({ text }) {
    return <div dangerouslySetInnerHTML={{ __html: text }} />;
}
