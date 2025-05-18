const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const path = require('path');
const multer = require('multer');
const fs = require('fs');
const messagesFile = path.join(__dirname, 'messages.json');
const app = express();
app.use(express.json()); // permet de lire les données JSON envoyées dans req.body

app.use(express.urlencoded({ extended: true }));

const server = http.createServer(app);
const io = socketIo(server);
const privateMessagesFile = path.join(__dirname, 'private-messages.json');

const users = {};
const dmUsers = {}; // Pour les discussions privées

const sqlite3 = require('sqlite3').verbose();
const db = new sqlite3.Database(process.env.DB_PATH || './users.db');


// Créer la table si elle n'existe pas
db.serialize(() => {
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      question TEXT,
      answer TEXT,
      online INTEGER DEFAULT 0
    );
  `);
});




// ➤ Créer le dossier uploads s’il n'existe pas
const uploadDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir);
}

// ➤ Configuration de multer avec conservation de l'extension
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, uploadDir);
  },
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname);
    const baseName = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, baseName + ext);
  }
});
const upload = multer({
  storage,
  limits: { fileSize: 100 * 1024 * 1024 * 1024 } // 100 Go
}
);

function updateUserList() {
  const usernames = Object.values(users);
  io.emit('user_list', usernames);
}


// Charger les messages sauvegardés
function loadMessages() {
  try {
    const data = fs.readFileSync(messagesFile);
    return JSON.parse(data);
  } catch (err) {
    return [];
  }
}

// Sauvegarder un nouveau message
function saveMessage(message) {
  try {
    const messages = loadMessages();
    messages.push(message);
    fs.writeFileSync(messagesFile, JSON.stringify(messages, null, 2));
  } catch (err) {
    console.error('Erreur de sauvegarde du message :', err);
  }
}

function loadPrivateMessages() {
  try {
    const data = fs.readFileSync(privateMessagesFile);
    return JSON.parse(data);
  } catch (err) {
    return [];
  }
}

function savePrivateMessage(messageObj) {
  try {
    const messages = loadPrivateMessages();
    messages.push(messageObj);
    fs.writeFileSync(privateMessagesFile, JSON.stringify(messages, null, 2));
  } catch (err) {
    console.error("❌ Erreur de sauvegarde DM :", err);
  }
}

app.post('/reset-password', async (req, res) => {
  const { username, question, answer, newPassword } = req.body;

  db.get(
    'SELECT * FROM users WHERE username = ?',
    [username],
    async (err, user) => {
      if (err || !user) {
        return res.status(404).json({ message: 'Utilisateur non trouvé' });
      }

      if (user.question !== question || user.answer !== answer) {
        return res.status(401).json({ message: 'Question ou réponse incorrecte.' });
      }

      const saltRounds = parseInt(process.env.SALT_ROUNDS) || 10;
      const hashedPassword = await bcrypt.hash(newPassword, saltRounds);

      db.run(
        'UPDATE users SET password = ? WHERE username = ?',
        [hashedPassword, username],
        (err) => {
          if (err) {
            return res.status(500).json({ message: 'Erreur lors de la mise à jour.' });
          }
          res.json({ message: 'Mot de passe réinitialisé avec succès ✅' });
        }
      );
    }
  );
});



// ➤ Route vers la page de connexion
app.get('/', (req, res) => {
  res.sendFile(path.resolve(__dirname, 'public', 'login.html'));
});

// ➤ Route vers la page de chat
app.get('/chat', (req, res) => {
  res.sendFile(path.resolve(__dirname, 'public', 'index.html'));
});

// ➤ Route vers la page de connexion DM
app.get('/dm-login', (req, res) => {
  res.sendFile(path.resolve(__dirname, 'public', 'dm-login.html'));
});

// ➤ Route vers la page de chat privé
app.get('/dm-chat', (req, res) => {
  res.sendFile(path.resolve(__dirname, 'public', 'dm-chat.html'));
});


// ➤ Servir les fichiers statiques
app.use(express.static(path.join(__dirname, 'public')));
app.get('/uploads/:filename', (req, res, next) => {
  const filePath = path.join(uploadDir, req.params.filename);
  const ext = path.extname(filePath).toLowerCase();

  if (ext === '.pdf' && fs.existsSync(filePath)) {
    res.sendFile(filePath, {
      headers: {
        'Content-Type': 'application/pdf',
        'Content-Disposition': 'inline',
        'X-Content-Type-Options': 'nosniff'
      }
    });
  } else {
    next(); // laisser les autres fichiers (images, etc.) passer à static()
  }
});

app.use('/uploads', express.static(uploadDir));

// ➤ Route de réception des fichiers
app.post('/send-file', upload.single('file'), (req, res) => {
  if (!req.file) {
    return res.status(400).send('Aucun fichier sélectionné.');
  }

  const fileUrl = `/uploads/${req.file.filename}`;
  res.json({ fileUrl });
});

// ➤ Socket.io
io.on('connection', (socket) => {
  console.log('✅ Utilisateur connecté');
  
    socket.on('connected_users_request', updateConnectedUsers);

    socket.on('typing', (isTyping) => {
    const username = users[socket.id];
    if (username) {
      socket.broadcast.emit('user_typing', { username, isTyping });
    }
  });
   
    // Envoyer l'historique à l'utilisateur
  const history = loadMessages();
  socket.emit('chat_history', history);

// Enregistrement d’un utilisateur connecté dans la base
socket.on('dm_register', (username) => {
  dmUsers[username] = socket;

  db.run('UPDATE users SET online = 1 WHERE username = ?', [username]);
  updateConnectedUsers();
});

// Fonction qui émet à tous les utilisateurs connectés
function updateConnectedUsers() {
  db.all('SELECT username FROM users WHERE online = 1', [], (err, rows) => {
    if (!err) {
      const userList = rows.map(row => row.username);
      io.emit('connected_users', userList);
    }
  });
}

// Gestion de la déconnexion
socket.on('disconnect', () => {
  const username = Object.keys(dmUsers).find(key => dmUsers[key] === socket);
  if (username) {
    db.run('UPDATE users SET online = 0 WHERE username = ?', [username]);
    delete dmUsers[username];
    updateConnectedUsers();
  }
});


socket.on('set_username', (name) => {
  users[socket.id] = name;
  console.log(`👤 Username: ${name}`);
  socket.broadcast.emit('receive_message', {
    message: `${name} a rejoint la conversation`,
    sender: 'System'
  });
  updateUserList();
});



// Réception et transmission de messages privés
socket.on('private_message', ({ to, message }) => {
  const sender = Object.keys(dmUsers).find(key => dmUsers[key] === socket);

  // Sauvegarder le message
  savePrivateMessage({
    from: sender,
    to,
    message,
    timestamp: Date.now()
  });

  if (dmUsers[to]) {
    dmUsers[to].emit('private_message', { from: sender, message });
  } else {
    socket.emit('private_message', {
      from: 'Système',
      message: `❌ L'utilisateur ${to} n'est pas connecté.`
    });
  }
});

socket.on('request_dm_history', (otherUser) => {
  const sender = Object.keys(dmUsers).find(key => dmUsers[key] === socket);

  if (!sender) return;

  // Charger tous les messages privés
  const allMessages = loadPrivateMessages();

  // Filtrer les messages entre sender et otherUser
  const history = allMessages.filter(msg =>
    (msg.from === sender && msg.to === otherUser) ||
    (msg.to === sender && msg.from === otherUser)
  );

  // Envoyer l'historique à l'utilisateur
  socket.emit('dm_history', history);
});


socket.on('send_message', (data) => {
    const username = users[socket.id] || 'Anonyme';
  
    const messageObj = {
      message: data.message,
      sender: username,
      timestamp: Date.now()
    };
  
    saveMessage(messageObj);
  
    socket.broadcast.emit('receive_message', messageObj);
  });
  

  socket.on('disconnect', () => {
    const username = users[socket.id];
    if (username) {
      socket.broadcast.emit('receive_message', {
        message: `${username} a quitté la conversation`,
        sender: 'System'
      });
      delete users[socket.id];
      updateUserList();
          // Supprimer aussi du registre DM
          const dmUsername = Object.keys(dmUsers).find(key => dmUsers[key] === socket);
          if (dmUsername) {
            delete dmUsers[dmUsername];
          }

    }
    console.log('❌ Utilisateur déconnecté');
  });
});

const bcrypt = require('bcrypt');
app.use(express.json());

// ➤ Inscription
app.post('/register', async (req, res) => {
  const { username, password, question, answer } = req.body;
  const saltRounds = parseInt(process.env.SALT_ROUNDS) || 10;
  const hash = await bcrypt.hash(password, saltRounds);


 db.run(
  'INSERT INTO users (username, password, question, answer) VALUES (?, ?, ?, ?)',
  [username, hash, question, answer],
    function (err) {
      if (err) {
        return res.status(400).json({ message: 'Nom déjà utilisé' });
      }
      res.json({ message: 'Inscription réussie' });
    }
  );
});

// ➤ Connexion
app.post('/login', (req, res) => {
  const { username, password } = req.body;

  db.get('SELECT * FROM users WHERE username = ?', [username], async (err, user) => {
    if (err || !user) {
      return res.status(401).json({ message: 'Utilisateur non trouvé' });
    }

    const match = await bcrypt.compare(password, user.password);
    if (!match) {
      return res.status(401).json({ message: 'Mot de passe incorrect' });
    }

    db.run('UPDATE users SET online = 1 WHERE username = ?', [username]);
    res.json({ success: true });
  });
});



// ➤ Démarrer le serveur
const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`🚀 Serveur lancé sur http://localhost:${PORT}`);

});
