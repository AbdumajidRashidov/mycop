const crypto = require('crypto');
const path = require('path');

// Safe - textContent instead of innerHTML
function renderComment(comment) {
    document.getElementById('comments').textContent = comment;
}

// Safe random
function generateId() {
    return crypto.randomUUID();
}

// Safe path handling
function readUserFile(req, res) {
    const filename = path.basename(req.query.filename);
    const filePath = path.join('/uploads', filename);
    if (!filePath.startsWith('/uploads')) {
        return res.status(403).send('Forbidden');
    }
    fs.readFile(filePath, (err, data) => {
        res.send(data);
    });
}

// Safe - parameterized MongoDB query
async function findUser(req, res) {
    const username = String(req.body.username);
    const user = await db.collection('users').findOne({ username });
    res.json(user);
}
