require('dotenv').config();
const express = require('express');
const mysql = require('mysql2/promise');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const multer = require('multer');
const xlsx = require('xlsx');
const path = require('path');
const fs = require('fs');
const cors = require('cors'); // Opcional, pero recomendado

const app = express();
const SECRET_KEY = "mi_secreto_super_seguro_modelorama"; // Cámbialo por uno real en producción

// === MIDDLEWARES ===
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Carpetas públicas
app.use(express.static('public')); 
app.use('/uploads', express.static('uploads')); // Vital para ver las fotos

// === CONFIGURACIÓN MULTER (SUBIDA DE FOTOS) ===
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        if (!fs.existsSync('uploads')) fs.mkdirSync('uploads');
        cb(null, 'uploads/');
    },
    filename: function (req, file, cb) {
        // Nombre único: prod-TIMESTAMP-RANDOM.ext
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        cb(null, 'prod-' + uniqueSuffix + path.extname(file.originalname));
    }
});
const upload = multer({ storage: storage });

// === CONEXIÓN BASE DE DATOS ===
const db = mysql.createPool({
    host: process.env.DB_HOST || 'localhost',
    user: process.env.DB_USER || 'root',
    password: process.env.DB_PASSWORD || '', // Tu contraseña aquí
    database: process.env.DB_NAME || 'modelorama_db',
    timezone: 'local', // Importante para fechas correctas
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
});

// === MIDDLEWARES DE SEGURIDAD ===
function verificarToken(req, res, next) {
    const bearerHeader = req.headers['authorization'];
    if (typeof bearerHeader !== 'undefined') {
        const token = bearerHeader.split(' ')[1];
        jwt.verify(token, SECRET_KEY, (err, authData) => {
            if (err) return res.sendStatus(403);
            req.usuario = authData;
            next();
        });
    } else {
        res.sendStatus(403);
    }
}

function soloAdmin(req, res, next) {
    if (req.usuario && req.usuario.rol === 'admin') {
        next();
    } else {
        res.status(403).json({ error: "Acceso denegado: Se requieren permisos de Administrador" });
    }
}

// ==========================================
//                 RUTAS (API)
// ==========================================

// --- 1. AUTENTICACIÓN ---
app.post('/api/registro', async (req, res) => {
    const { nombre, email, password, rol } = req.body;
    try {
        const [exist] = await db.query('SELECT * FROM usuarios WHERE email = ?', [email]);
        if (exist.length > 0) return res.status(400).json({ error: "El correo ya está registrado" });
        
        const hash = await bcrypt.hash(password, 10);
        await db.query('INSERT INTO usuarios (nombre, email, password, rol) VALUES (?, ?, ?, ?)', [nombre, email, hash, rol]);
        res.status(201).json({ message: "Usuario registrado exitosamente" });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;
    try {
        const [users] = await db.query('SELECT * FROM usuarios WHERE email = ?', [email]);
        if (users.length === 0) return res.status(401).json({ error: "Usuario no encontrado" });
        
        const user = users[0];
        if (await bcrypt.compare(password, user.password)) {
            const token = jwt.sign({ id: user.id, rol: user.rol, nombre: user.nombre }, SECRET_KEY, { expiresIn: '12h' });
            res.json({ message: "Bienvenido", token, rol: user.rol, usuario: user.nombre });
        } else {
            res.status(401).json({ error: "Contraseña incorrecta" });
        }
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// --- 2. PRODUCTOS (CRUD COMPLETO) ---

// Obtener todos
app.get('/api/productos', verificarToken, async (req, res) => {
    try {
        const sql = `
            SELECT p.*, 
            GROUP_CONCAT(c.nombre SEPARATOR ', ') as categorias_nombres, 
            GROUP_CONCAT(c.id) as categorias_ids 
            FROM productos p 
            LEFT JOIN producto_categorias pc ON p.id = pc.producto_id 
            LEFT JOIN categorias c ON pc.categoria_id = c.id 
            GROUP BY p.id
        `;
        const [rows] = await db.query(sql);
        res.json(rows);
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// Obtener uno (para editar)
app.get('/api/productos/:id', verificarToken, async (req, res) => {
    try {
        const [rows] = await db.query(`
            SELECT p.*, GROUP_CONCAT(pc.categoria_id) as cats 
            FROM productos p 
            LEFT JOIN producto_categorias pc ON p.id = pc.producto_id 
            WHERE p.id = ? GROUP BY p.id`, [req.params.id]);
            
        if(rows.length === 0) return res.status(404).json({error:"No existe"});
        
        const prod = rows[0];
        prod.categorias_ids = prod.cats ? prod.cats.split(',').map(Number) : [];
        res.json(prod);
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// CREAR (POST)
app.post('/api/productos', verificarToken, soloAdmin, upload.single('imagen'), async (req, res) => {
    const { nombre, codigo_barras, precio_compra, precio_venta, stock_actual, ubicacion, categorias } = req.body;
    const imagen = req.file ? req.file.filename : null;
    const connection = await db.getConnection();
    
    try {
        await connection.beginTransaction();
        const [resProd] = await connection.query(
            'INSERT INTO productos (nombre, codigo_barras, precio_compra, precio_venta, stock_actual, ubicacion, imagen) VALUES (?, ?, ?, ?, ?, ?, ?)',
            [nombre, codigo_barras, precio_compra||0, precio_venta, stock_actual||0, ubicacion, imagen]
        );
        const pid = resProd.insertId;

        // Categorías
        if (categorias) {
            const catArr = categorias.split(',').filter(x=>x);
            if(catArr.length > 0) {
                const rels = catArr.map(c => [pid, c]);
                await connection.query('INSERT INTO producto_categorias (producto_id, categoria_id) VALUES ?', [rels]);
            }
        }
        
        // Historial
        await connection.query('INSERT INTO historial (usuario, accion, detalle) VALUES (?, ?, ?)', 
            [req.usuario.nombre, 'CREAR', `Creó: ${nombre} (ID: ${pid})`]);
        
        await connection.commit();
        res.status(201).json({ message: "Producto creado" });
    } catch (e) {
        await connection.rollback();
        console.error(e); res.status(500).json({ error: e.message });
    } finally { connection.release(); }
});

// EDITAR (PUT) - Lógica Robusta
app.put('/api/productos/:id', verificarToken, soloAdmin, upload.single('imagen'), async (req, res) => {
    const { id } = req.params;
    const { nombre, codigo_barras, precio_compra, precio_venta, stock_actual, ubicacion, categorias } = req.body;
    const nuevaImagen = req.file ? req.file.filename : null;

    const connection = await db.getConnection();
    try {
        await connection.beginTransaction();

        // Construcción dinámica de SQL
        let sql = 'UPDATE productos SET nombre=?, codigo_barras=?, precio_compra=?, precio_venta=?, stock_actual=?, ubicacion=?';
        let params = [nombre, codigo_barras, precio_compra, precio_venta, stock_actual, ubicacion];

        if(nuevaImagen) {
            sql += ', imagen=?';
            params.push(nuevaImagen);
        }
        sql += ' WHERE id=?';
        params.push(id);

        await connection.query(sql, params);

        // Actualizar Categorías (Borrar viejas e insertar nuevas)
        if(categorias !== undefined) {
            await connection.query('DELETE FROM producto_categorias WHERE producto_id = ?', [id]);
            const catArr = categorias.toString().split(',').filter(x => x);
            if(catArr.length > 0) {
                const rels = catArr.map(c => [id, c]);
                await connection.query('INSERT INTO producto_categorias (producto_id, categoria_id) VALUES ?', [rels]);
            }
        }

        // Historial
        await connection.query('INSERT INTO historial (usuario, accion, detalle) VALUES (?, ?, ?)', 
            [req.usuario.nombre, 'EDITAR', `Editó producto ID: ${id}`]);

        await connection.commit();
        res.json({ message: "Producto actualizado" });
    } catch (e) {
        await connection.rollback();
        console.error(e); res.status(500).json({ error: e.message });
    } finally { connection.release(); }
});

// ELIMINAR (DELETE)
app.delete('/api/productos/:id', verificarToken, soloAdmin, async (req, res) => {
    const connection = await db.getConnection();
    try {
        await connection.beginTransaction();
        
        // Obtener nombre para historial
        const [prod] = await connection.query('SELECT nombre FROM productos WHERE id=?', [req.params.id]);
        const pName = prod.length ? prod[0].nombre : 'Desconocido';

        await connection.query('DELETE FROM producto_categorias WHERE producto_id=?', [req.params.id]);
        await connection.query('DELETE FROM productos WHERE id=?', [req.params.id]);
        
        await connection.query('INSERT INTO historial (usuario, accion, detalle) VALUES (?, ?, ?)', 
            [req.usuario.nombre, 'ELIMINAR', `Eliminó: ${pName}`]);

        await connection.commit();
        res.json({ message: "Eliminado" });
    } catch(e) { await connection.rollback(); res.status(500).json({ error: e.message }); } finally { connection.release(); }
});

// --- 3. CATEGORÍAS ---
app.get('/api/categorias', verificarToken, async (req, res) => {
    const [rows] = await db.query('SELECT * FROM categorias ORDER BY nombre');
    res.json(rows);
});

// --- 4. VENTAS (PUNTO DE VENTA) ---
app.post('/api/ventas', verificarToken, async (req, res) => {
    const { carrito, total } = req.body;
    if(!carrito || !carrito.length) return res.status(400).json({error:"Carrito vacío"});

    const connection = await db.getConnection();
    try {
        await connection.beginTransaction();
        
        // Cabecera venta
        const [resV] = await connection.query('INSERT INTO ventas (usuario_id, total) VALUES (?, ?)', [req.usuario.id, total]);
        const ventaId = resV.insertId;

        // Detalle y resta de stock
        for (const item of carrito) {
            await connection.query('INSERT INTO detalle_ventas (venta_id, producto_id, cantidad, precio_unitario, subtotal) VALUES (?, ?, ?, ?, ?)', 
                [ventaId, item.id, item.cantidad, item.precio, item.cantidad*item.precio]);
            
            await connection.query('UPDATE productos SET stock_actual = stock_actual - ? WHERE id = ?', [item.cantidad, item.id]);
        }
        
        await connection.commit();
        res.json({ message: "Venta registrada", ticketId: ventaId });
    } catch(e) { await connection.rollback(); res.status(500).json({ error: e.message }); } finally { connection.release(); }
});

// --- 5. PEDIDOS WEB (CLIENTES) ---
app.post('/api/pedidos', verificarToken, async (req, res) => {
    const { carrito, total } = req.body;
    const connection = await db.getConnection();
    try {
        await connection.beginTransaction();
        const [resP] = await connection.query('INSERT INTO pedidos (cliente_id, total) VALUES (?, ?)', [req.usuario.id, total]);
        const pid = resP.insertId;
        
        for (const item of carrito) {
            await connection.query('INSERT INTO detalle_pedidos (pedido_id, producto_id, cantidad, precio_unitario, subtotal) VALUES (?, ?, ?, ?, ?)', 
                [pid, item.id, item.cantidad, item.precio, item.cantidad*item.precio]);
            // Opcional: Restar stock aquí o al entregar. Aquí lo restamos ya.
            await connection.query('UPDATE productos SET stock_actual = stock_actual - ? WHERE id = ?', [item.cantidad, item.id]);
        }
        await connection.commit();
        res.json({ message: "Pedido realizado", pedidoId: pid });
    } catch(e) { await connection.rollback(); res.status(500).json({ error: e.message }); } finally { connection.release(); }
});

app.get('/api/pedidos/pendientes', verificarToken, async (req, res) => {
    const [rows] = await db.query("SELECT p.id, p.total, p.fecha, u.nombre as cliente FROM pedidos p JOIN usuarios u ON p.cliente_id=u.id WHERE p.estado='pendiente' ORDER BY p.fecha ASC");
    res.json(rows);
});

app.get('/api/pedidos/:id/detalle', verificarToken, async (req, res) => {
    const [rows] = await db.query("SELECT dp.*, p.nombre FROM detalle_pedidos dp JOIN productos p ON dp.producto_id=p.id WHERE dp.pedido_id=?", [req.params.id]);
    res.json(rows);
});

app.put('/api/pedidos/:id/entregar', verificarToken, async (req, res) => {
    await db.query("UPDATE pedidos SET estado='entregado' WHERE id=?", [req.params.id]);
    res.json({ message: "Entregado" });
});

// --- 6. CAJA (CORTE) ---
app.get('/api/caja/estado', verificarToken, async (req, res) => {
    const [rows] = await db.query('SELECT * FROM cortes_caja WHERE usuario_id=? AND estado="abierto"', [req.usuario.id]);
    res.json({ abierto: rows.length > 0, datos: rows[0] });
});

app.post('/api/caja/abrir', verificarToken, async (req, res) => {
    await db.query('INSERT INTO cortes_caja (usuario_id, monto_inicial) VALUES (?, ?)', [req.usuario.id, req.body.monto_inicial]);
    res.json({ message: "Caja abierta" });
});

app.post('/api/caja/cerrar', verificarToken, async (req, res) => {
    const [c] = await db.query('SELECT * FROM cortes_caja WHERE usuario_id=? AND estado="abierto"', [req.usuario.id]);
    if(c.length === 0) return res.status(400).json({error:"No hay caja abierta"});
    
    const inicio = parseFloat(c[0].monto_inicial);
    const [v] = await db.query('SELECT SUM(total) as t FROM ventas WHERE usuario_id=? AND fecha >= ?', [req.usuario.id, c[0].fecha_inicio]);
    const ventas = parseFloat(v[0].t || 0);
    const final = parseFloat(req.body.monto_final);
    const diff = final - (inicio + ventas);

    await db.query('UPDATE cortes_caja SET monto_final=?, total_ventas=?, diferencia=?, fecha_fin=NOW(), estado="cerrado" WHERE id=?', 
        [final, ventas, diff, c[0].id]);
        
    res.json({ resumen: { inicio, ventas, esperado: inicio+ventas, real: final, diferencia: diff } });
});

// --- 7. REPORTES Y GRÁFICAS ---
app.get('/api/reportes/ventas-semanales', verificarToken, async (req, res) => {
    // Usamos GROUP BY dia compatible
    const sql = `SELECT DATE_FORMAT(fecha, '%Y-%m-%d') as dia, SUM(total) as total FROM ventas WHERE fecha >= DATE_SUB(NOW(), INTERVAL 7 DAY) GROUP BY dia ORDER BY dia ASC`;
    const [rows] = await db.query(sql);
    res.json(rows);
});

app.get('/api/reportes/productos-top', verificarToken, async (req, res) => {
    const sql = `SELECT p.nombre, SUM(dv.cantidad) as cantidad_total FROM detalle_ventas dv JOIN productos p ON dv.producto_id=p.id GROUP BY p.id ORDER BY cantidad_total DESC LIMIT 5`;
    const [rows] = await db.query(sql);
    res.json(rows);
});

app.get('/api/reportes/detalle-dia/:fecha', verificarToken, async (req, res) => {
    const sql = `SELECT p.nombre, SUM(dv.cantidad) as c, SUM(dv.subtotal) as t FROM ventas v JOIN detalle_ventas dv ON v.id=dv.venta_id JOIN productos p ON dv.producto_id=p.id WHERE DATE(v.fecha)=? GROUP BY p.id`;
    const [rows] = await db.query(sql, [req.params.fecha]);
    res.json(rows);
});

app.get('/api/historial', verificarToken, async (req, res) => {
    const [rows] = await db.query("SELECT * FROM historial ORDER BY fecha DESC LIMIT 50");
    res.json(rows);
});

// --- 8. EXCEL ---
app.get('/api/exportar', async (req, res) => {
    const [rows] = await db.query("SELECT * FROM productos");
    const wb = xlsx.utils.book_new();
    xlsx.utils.book_append_sheet(wb, xlsx.utils.json_to_sheet(rows), "Inventario");
    const buf = xlsx.write(wb, { type: 'buffer', bookType: 'xlsx' });
    res.setHeader('Content-Disposition', 'attachment; filename="Inventario.xlsx"');
    res.send(buf);
});

app.post('/api/importar', upload.single('archivoExcel'), async (req, res) => {
    // Lógica básica para leer Excel
    if(!req.file) return res.status(400).json({error:"Falta archivo"});
    try {
        const wb = xlsx.readFile(req.file.path);
        const data = xlsx.utils.sheet_to_json(wb.Sheets[wb.SheetNames[0]]);
        
        const connection = await db.getConnection();
        await connection.beginTransaction();
        for(const row of data) {
            // Asume columnas: Nombre, PrecioVenta, Stock
            if(row.Nombre && row.PrecioVenta) {
                await connection.query(
                    `INSERT INTO productos (nombre, precio_venta, stock_actual, precio_compra, ubicacion) VALUES (?, ?, ?, ?, ?) 
                     ON DUPLICATE KEY UPDATE stock_actual = stock_actual + VALUES(stock_actual)`,
                    [row.Nombre, row.PrecioVenta, row.Stock||0, row.PrecioCompra||0, row.Ubicacion||'']
                );
            }
        }
        await connection.commit();
        connection.release();
        res.json({message: "Importación completada"});
    } catch(e) { console.error(e); res.status(500).json({error:"Error procesando Excel"}); }
});

// Redirigir raíz
app.get('/', (req, res) => res.redirect('/index.html'));

// INICIAR SERVIDOR
const PORT = 3000;
app.listen(PORT, () => console.log(`Servidor corriendo en puerto ${PORT}`));