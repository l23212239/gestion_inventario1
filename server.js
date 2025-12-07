const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const app = express();
const path = require('path');
const bodyParser = require('body-parser');
const mysql = require('mysql2');
const multer = require('multer'); 
const xlsx = require('xlsx');
require('dotenv').config();
app.use(express.json());

// Configuración de Multer para guardar en /uploads
const upload = multer({ dest: 'uploads/' });

// Configuración de la sesión
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
}));

// Configurar conexión a MySQL
const connection = mysql.createConnection({
  host: process.env.DB_HOST,      
  user: process.env.DB_USER,      
  password: process.env.DB_PASSWORD, 
  database: process.env.DB_NAME,
  timezone: 'America/Tijuana'     
});

connection.connect(err => {
  if (err) {
    console.error('Error conectando a MySQL:', err);
    return;
  }
  console.log('Conexión exitosa a MySQL');
});







// === RUTA DE REGISTRO DE USUARIOS ===
app.post('/api/registro', async (req, res) => {
    const { nombre, email, password, rol } = req.body;

    if (!nombre || !email || !password || !rol) {
        return res.status(400).json({ error: "Por favor llene todos los campos" });
    }

    try {
        const [userExist] = await db.query('SELECT * FROM usuarios WHERE email = ?', [email]);
        if (userExist.length > 0) {
            return res.status(400).json({ error: "El correo ya está registrado" });
        }

        const salt = await bcrypt.genSalt(10);
        const passwordHash = await bcrypt.hash(password, salt);

        const sql = 'INSERT INTO usuarios (nombre, email, password, rol) VALUES (?, ?, ?, ?)';
        await db.query(sql, [nombre, email, passwordHash, rol]);

        res.status(201).json({ message: "Usuario registrado exitosamente" });

    } catch (error) {
        console.error(error);
        res.status(500).json({ error: "Error en el servidor al registrar usuario" });
    }
});

// ... resto de tu código (app.listen, etc)