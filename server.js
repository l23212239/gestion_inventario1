require('dotenv').config();
const express = require('express');
const mysql = require('mysql2/promise');
const SECRET_KEY = "mi_secreto_super_seguro";
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const app = express();
const path = require('path');
const bodyParser = require('body-parser');
const multer = require('multer'); 
const upload = multer({ dest: 'uploads/' });
const xlsx = require('xlsx');
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));

// Configurar conexión a MySQL
const db = mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    timezone: 'local', 
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
});
db.getConnection()
    .then(connection => {
        console.log('¡Conectado exitosamente a la Base de Datos!');
        connection.release();
    })
    .catch(error => {
        console.error('Error conectando a la BD:', error.code);
        console.error('Verifica que XAMPP/MySQL esté prendido y los datos sean correctos.');
    });

// === MIDDLEWARE DE VERIFICACIÓN DE TOKEN ===
function verificarToken(req, res, next) {
    const bearerHeader = req.headers['authorization']; 
    
    if (typeof bearerHeader !== 'undefined') {
        const bearer = bearerHeader.split(' ');
        const token = bearer[1];
        
        jwt.verify(token, SECRET_KEY, (err, authData) => {
            if (err) {
                res.sendStatus(403); 
            } else {
                req.usuario = authData; 
                next(); 
            }
        });
    } else {
        res.sendStatus(403);
    }
}

// === MIDDLEWARE PARA SOLO ADMINS ===
function soloAdmin(req, res, next) {
    if (req.usuario && req.usuario.rol === 'admin') {
        next();
    } else {
        res.status(403).json({ error: "Acceso denegado: Se requieren permisos de Administrador" });
    }
}

// === RUTA DE REGISTRO DE USUARIOS ===
app.post('/api/registro', async (req, res) => {
    console.log("--> 1. Petición de registro recibida");
    console.log("--> 2. Datos recibidos (Body):", req.body);

    const { nombre, email, password, rol } = req.body;

    if (!nombre || !email || !password || !rol) {
        console.log("--> ERROR: Faltan campos en el body");
        return res.status(400).json({ error: "Faltan datos. Revisa la consola del servidor." });
    }

    try {
        console.log("--> 3. Buscando si el correo existe...");
        const [userExist] = await db.query('SELECT * FROM usuarios WHERE email = ?', [email]);
        
        if (userExist.length > 0) {
            console.log("--> ERROR: El correo ya existe");
            return res.status(400).json({ error: "El correo ya está registrado" });
        }

        console.log("--> 4. Encriptando contraseña...");
        const salt = await bcrypt.genSalt(10);
        const passwordHash = await bcrypt.hash(password, salt);

        const sql = 'INSERT INTO usuarios (nombre, email, password, rol) VALUES (?, ?, ?, ?)';
        const [result] = await db.query(sql, [nombre, email, passwordHash, rol]);

        console.log("--> ¡ÉXITO! Usuario creado con ID:", result.insertId);
        res.status(201).json({ message: "Usuario registrado exitosamente" });

    } catch (error) {
        console.error("--> ERROR CRÍTICO SQL:", error);
        res.status(500).json({ error: error.message || "Error en el servidor" });
    }
});

// === RUTA DE LOGIN ===
app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ error: "Faltan datos" });
    }

    try {
        // 1. Buscar al usuario por email
        const [users] = await db.query('SELECT * FROM usuarios WHERE email = ?', [email]);
        
        // Si no existe el usuario
        if (users.length === 0) {
            return res.status(401).json({ error: "Usuario o contraseña incorrectos" });
        }

        const usuario = users[0];

        // 2. Comparar contraseñas (La que escribe vs La encriptada en BD)
        const validPassword = await bcrypt.compare(password, usuario.password);

        if (!validPassword) {
            return res.status(401).json({ error: "Usuario o contraseña incorrectos" });
        }

        // 3. Crear el Token (El "Gafete" de acceso)
        // Guardamos su ID y su ROL dentro del token
        const token = jwt.sign(
            { id: usuario.id, rol: usuario.rol, nombre: usuario.nombre },
            SECRET_KEY,
            { expiresIn: '8h' } // La sesión dura 8 horas
        );

        // 4. Responder con éxito
        res.json({
            message: "Bienvenido",
            token: token,
            rol: usuario.rol,
            usuario: usuario.nombre
        });

    } catch (error) {
        console.error(error);
        res.status(500).json({ error: "Error en el servidor" });
    }
});

// === CREAR PRODUCTO (CREATE) ===
app.post('/api/productos', verificarToken, soloAdmin,async (req, res) => {
    const { nombre, codigo_barras, precio_compra, precio_venta, stock_actual, ubicacion, categorias } = req.body;
    const nombreUsuario = req.usuario.nombre; // <--- Obtenemos quién está haciendo esto

    // Validaciones
    if (!nombre || !precio_venta) {
        return res.status(400).json({ error: "Nombre y Precio de Venta son obligatorios" });
    }

    const connection = await db.getConnection();
    
    try {
        await connection.beginTransaction(); // --- INICIO TRANSACCIÓN ---

        // 1. Insertar el Producto
        const sqlProd = `
            INSERT INTO productos 
            (nombre, codigo_barras, precio_compra, precio_venta, stock_actual, ubicacion) 
            VALUES (?, ?, ?, ?, ?, ?)
        `;
        const [result] = await connection.query(sqlProd, [
            nombre, codigo_barras, precio_compra || 0, precio_venta, stock_actual || 0, ubicacion
        ]);
        
        const nuevoId = result.insertId;

        // 2. Insertar Categorías (Si hay)
        if (categorias && categorias.length > 0) {
            const relaciones = categorias.map(catId => [nuevoId, catId]);
            await connection.query(
                'INSERT INTO producto_categorias (producto_id, categoria_id) VALUES ?', 
                [relaciones]
            );
        }

        // 3. --- NUEVO: REGISTRAR EN HISTORIAL ---
        await connection.query(
            'INSERT INTO historial (usuario, accion, detalle) VALUES (?, ?, ?)',
            [nombreUsuario, 'CREAR', `Se creó el producto: ${nombre} (ID: ${nuevoId})`]
        );

        await connection.commit(); // --- CONFIRMAR CAMBIOS ---
        connection.release();

        res.status(201).json({ message: "Producto creado exitosamente", id: nuevoId });

    } catch (error) {
        await connection.rollback(); // --- ERROR: DESHACER TODO ---
        connection.release();
        console.error("Error creando producto:", error);
        res.status(500).json({ error: "Error al guardar el producto" });
    }
});

// === RUTA PRIVADA: OBTENER TODOS LOS PRODUCTOS (READ)===
app.get('/api/productos', verificarToken, async (req, res) => {
    try {
        const sql = `
            SELECT p.*, GROUP_CONCAT(c.nombre SEPARATOR ', ') as categorias_nombres
            FROM productos p
            LEFT JOIN producto_categorias pc ON p.id = pc.producto_id
            LEFT JOIN categorias c ON pc.categoria_id = c.id
            GROUP BY p.id
        `;
        
        const [productos] = await db.query(sql);
        res.json(productos);
        
    } catch (error) {
        console.error(error);
        res.status(500).send("Error al obtener productos");
    }
});


// === EDITAR PRODUCTO (UPDATE) ===
app.put('/api/productos/:id', verificarToken, soloAdmin,async (req, res) => {
    const { id } = req.params;
    const { nombre, codigo_barras, precio_compra, precio_venta, stock_actual, ubicacion, categorias } = req.body;

    const connection = await db.getConnection();

    try {
        await connection.beginTransaction();

        const sqlUpdate = `
            UPDATE productos SET 
            nombre = ?, codigo_barras = ?, precio_compra = ?, 
            precio_venta = ?, stock_actual = ?, ubicacion = ?
            WHERE id = ?
        `;
        await connection.query(sqlUpdate, [
            nombre, codigo_barras, precio_compra, precio_venta, stock_actual, ubicacion, id
        ]);

        if (categorias) {
            await connection.query('DELETE FROM producto_categorias WHERE producto_id = ?', [id]);

            if (categorias.length > 0) {
                const relaciones = categorias.map(catId => [id, catId]);
                await connection.query(
                    'INSERT INTO producto_categorias (producto_id, categoria_id) VALUES ?', 
                    [relaciones]
                );
            }
        }

        await connection.commit();
        connection.release();
        res.json({ message: "Producto actualizado correctamente" });

    } catch (error) {
        await connection.rollback();
        connection.release();
        console.error("Error actualizando:", error);
        res.status(500).json({ error: "Error al actualizar producto" });
    }
});

// === ELIMINAR PRODUCTO (DELETE) ===
app.delete('/api/productos/:id', verificarToken, soloAdmin,async (req, res) => {
    const { id } = req.params;
    const nombreUsuario = req.usuario.nombre; // Viene del token

    const connection = await db.getConnection();
    
    try {
        await connection.beginTransaction();

        const [prod] = await connection.query('SELECT nombre FROM productos WHERE id = ?', [id]);
        const nombreProducto = prod.length > 0 ? prod[0].nombre : 'Desconocido';

        await connection.query('DELETE FROM producto_categorias WHERE producto_id = ?', [id]);
        const [result] = await connection.query('DELETE FROM productos WHERE id = ?', [id]);

        if (result.affectedRows === 0) {
            await connection.rollback();
            connection.release();
            return res.status(404).json({ error: "Producto no encontrado" });
        }

        await connection.query(
            'INSERT INTO historial (usuario, accion, detalle) VALUES (?, ?, ?)',
            [nombreUsuario, 'ELIMINAR', `Se eliminó el producto: ${nombreProducto} (ID: ${id})`]
        );

        await connection.commit();
        connection.release();
        res.json({ message: "Producto eliminado y registrado en historial" });

    } catch (error) {
        await connection.rollback();
        connection.release();
        console.error("Error eliminando:", error);
        res.status(500).json({ error: "Error al eliminar" });
    }
});

// === OBTENER UN SOLO PRODUCTO (GET /:id) ===
app.get('/api/productos/:id', verificarToken, async (req, res) => {
    try {
        const sql = `
            SELECT p.*, 
            GROUP_CONCAT(pc.categoria_id) as categorias_ids
            FROM productos p
            LEFT JOIN producto_categorias pc ON p.id = pc.producto_id
            WHERE p.id = ?
            GROUP BY p.id
        `;
        const [rows] = await db.query(sql, [req.params.id]);

        if (rows.length === 0) return res.status(404).json({ error: "No encontrado" });

        const producto = rows[0];
        
        if (producto.categorias_ids) {
            producto.categorias_ids = producto.categorias_ids.split(',').map(Number);
        } else {
            producto.categorias_ids = [];
        }

        res.json(producto);

    } catch (error) {
        console.error(error);
        res.status(500).send("Error del servidor");
    }
});

// === OBTENER TODAS LAS CATEGORÍAS (Para el selector del Modal) ===
app.get('/api/categorias', verificarToken, async (req, res) => {
    try {
        const [categorias] = await db.query('SELECT * FROM categorias ORDER BY nombre ASC');
        res.json(categorias);
    } catch (error) {
        console.error(error);
        res.status(500).send("Error al obtener categorías");
    }
});

// === EXPORTAR A EXCEL (GET) ===
app.get('/api/exportar', async (req, res) => {
    try {
       
        const sql = `
            SELECT p.id, p.nombre, p.codigo_barras, p.precio_compra, p.precio_venta, p.stock_actual, p.ubicacion,
            GROUP_CONCAT(c.nombre SEPARATOR ', ') as categorias
            FROM productos p
            LEFT JOIN producto_categorias pc ON p.id = pc.producto_id
            LEFT JOIN categorias c ON pc.categoria_id = c.id
            GROUP BY p.id
        `;
        const [rows] = await db.query(sql);

        const workbook = xlsx.utils.book_new();
        const worksheet = xlsx.utils.json_to_sheet(rows);
        xlsx.utils.book_append_sheet(workbook, worksheet, "Inventario");

        const buffer = xlsx.write(workbook, { type: 'buffer', bookType: 'xlsx' });
        res.setHeader('Content-Disposition', 'attachment; filename="Inventario_Modelorama.xlsx"');
        res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
        res.send(buffer);

    } catch (error) {
        console.error("Error exportando:", error);
        res.status(500).send("Error al generar el Excel");
    }
});

// === 3. RUTA: IMPORTAR EXCEL (POST) ===
app.post('/api/importar', upload.single('archivoExcel'), soloAdmin, async (req, res) => {
    if (!req.file) return res.status(400).json({ error: "No se subió ningún archivo" });

    try {
        const workbook = xlsx.readFile(req.file.path);
        const sheetName = workbook.SheetNames[0];
        const data = xlsx.utils.sheet_to_json(workbook.Sheets[sheetName]);

        const connection = await db.getConnection();
        await connection.beginTransaction();

        for (const row of data) {
            if (!row.Nombre || !row.PrecioVenta) continue; 

            const sqlProd = `
                INSERT INTO productos (nombre, codigo_barras, precio_compra, precio_venta, stock_actual, ubicacion)
                VALUES (?, ?, ?, ?, ?, ?)
                ON DUPLICATE KEY UPDATE 
                stock_actual = stock_actual + VALUES(stock_actual), -- <--- AQUÍ SUMA EL STOCK
                precio_venta = VALUES(precio_venta),
                precio_compra = VALUES(precio_compra),
                ubicacion = VALUES(ubicacion)
            `;
            
            const [result] = await connection.query(sqlProd, [
                row.Nombre, row.Codigo || null, row.PrecioCompra || 0, row.PrecioVenta, row.Stock || 0, row.Ubicacion || ''
            ]);

            let productoId = result.insertId;
            if (productoId === 0) {
                const [existing] = await connection.query('SELECT id FROM productos WHERE nombre = ?', [row.Nombre]);
                productoId = existing[0].id;
            }

            if (row.Categorias) {
                const catsArray = row.Categorias.split(',').map(c => c.trim());
                
                for (const catNombre of catsArray) {
                    if(!catNombre) continue;

                    let [catResult] = await connection.query('SELECT id FROM categorias WHERE nombre = ?', [catNombre]);
                    let catId;
                    
                    if (catResult.length > 0) {
                        catId = catResult[0].id;
                    } else {
                        const [newCat] = await connection.query('INSERT INTO categorias (nombre) VALUES (?)', [catNombre]);
                        catId = newCat.insertId;
                    }

                    await connection.query(
                        'INSERT IGNORE INTO producto_categorias (producto_id, categoria_id) VALUES (?, ?)',
                        [productoId, catId]
                    );
                }
            }
        }

        await connection.commit();
        connection.release();
        res.json({ message: "Importación completada exitosamente" });

    } catch (error) {
        console.error(error);
        res.status(500).json({ error: "Error procesando el archivo Excel" });
    }
});

// === REGISTRAR VENTA (Resta stock y genera ticket) ===
app.post('/api/ventas', verificarToken, async (req, res) => {
    const { carrito, total } = req.body; 
    const usuarioId = req.usuario.id; 

    if (!carrito || carrito.length === 0) {
        return res.status(400).json({ error: "El carrito está vacío" });
    }

    const connection = await db.getConnection();

    try {
        await connection.beginTransaction(); 

        const [ventaResult] = await connection.query(
            'INSERT INTO ventas (usuario_id, total) VALUES (?, ?)',
            [usuarioId, total]
        );
        const ventaId = ventaResult.insertId;

        for (const item of carrito) {
            await connection.query(
                'INSERT INTO detalle_ventas (venta_id, producto_id, cantidad, precio_unitario, subtotal) VALUES (?, ?, ?, ?, ?)',
                [ventaId, item.id, item.cantidad, item.precio, (item.precio * item.cantidad)]
            );

            await connection.query(
                'UPDATE productos SET stock_actual = stock_actual - ? WHERE id = ?',
                [item.cantidad, item.id]
            );
        }

        await connection.commit();
        connection.release();

        res.json({ message: "Venta registrada", ticketId: ventaId });

    } catch (error) {
        await connection.rollback();
        connection.release();
        console.error("Error en venta:", error);
        res.status(500).json({ error: "Error al procesar la venta" });
    }
});

// === A. VERIFICAR SI HAY CAJA ABIERTA ===
app.get('/api/caja/estado', verificarToken, async (req, res) => {
    try {
        // Buscamos si este usuario tiene un corte con estado 'abierto'
        const [corte] = await db.query(
            'SELECT * FROM cortes_caja WHERE usuario_id = ? AND estado = "abierto"', 
            [req.usuario.id]
        );
        
        if (corte.length > 0) {
            res.json({ abierto: true, datos: corte[0] });
        } else {
            res.json({ abierto: false });
        }
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: "Error al verificar caja" });
    }
});

// === B. ABRIR CAJA ===
app.post('/api/caja/abrir', verificarToken, async (req, res) => {
    const { monto_inicial } = req.body;
    const usuario_id = req.usuario.id;

    try {
        // Verificar que no tenga ya una abierta
        const [existente] = await db.query(
            'SELECT id FROM cortes_caja WHERE usuario_id = ? AND estado = "abierto"',
            [usuario_id]
        );
        
        if (existente.length > 0) {
            return res.status(400).json({ error: "Ya tienes una caja abierta." });
        }

        await db.query(
            'INSERT INTO cortes_caja (usuario_id, monto_inicial) VALUES (?, ?)',
            [usuario_id, monto_inicial]
        );

        res.json({ message: "Caja abierta exitosamente." });

    } catch (error) {
        console.error(error);
        res.status(500).json({ error: "Error al abrir caja" });
    }
});

// === C. CERRAR CAJA (El cálculo matemático) ===
app.post('/api/caja/cerrar', verificarToken, async (req, res) => {
    const { monto_final } = req.body; // El dinero que el cajero contó
    const usuario_id = req.usuario.id;

    try {
        // 1. Obtener la caja abierta
        const [corte] = await db.query(
            'SELECT * FROM cortes_caja WHERE usuario_id = ? AND estado = "abierto"',
            [usuario_id]
        );

        if (corte.length === 0) return res.status(400).json({ error: "No hay caja abierta para cerrar." });
        
        const idCorte = corte[0].id;
        const fechaInicio = corte[0].fecha_inicio;
        const montoInicial = parseFloat(corte[0].monto_inicial);

        // 2. Sumar todas las ventas hechas por este usuario DESDE que abrió la caja
        const [ventas] = await db.query(
            'SELECT SUM(total) as total_vendido FROM ventas WHERE usuario_id = ? AND fecha >= ?',
            [usuario_id, fechaInicio]
        );
        
        const totalVendido = ventas[0].total_vendido || 0;
        
        // 3. Calcular matemáticas
        // Dinero esperado = Inicial + Ventas
        const dineroEsperado = montoInicial + parseFloat(totalVendido);
        // Diferencia = Dinero que hay fisicamente - Dinero esperado
        // Si sale negativo, falta dinero. Si sale positivo, sobra.
        const diferencia = parseFloat(monto_final) - dineroEsperado;

        // 4. Actualizar la base de datos
        await db.query(`
            UPDATE cortes_caja SET 
            monto_final = ?, 
            total_ventas = ?, 
            diferencia = ?, 
            fecha_fin = NOW(), 
            estado = 'cerrado' 
            WHERE id = ?`,
            [monto_final, totalVendido, diferencia, idCorte]
        );

        res.json({ 
            message: "Caja cerrada.", 
            resumen: {
                inicio: montoInicial,
                ventas: totalVendido,
                esperado: dineroEsperado,
                real: monto_final,
                diferencia: diferencia
            }
        });

    } catch (error) {
        console.error(error);
        res.status(500).json({ error: "Error al cerrar caja" });
    }
});

// === REPORTES: VENTAS DE LOS ÚLTIMOS 7 DÍAS ===
app.get('/api/reportes/ventas-semanales', verificarToken, async (req, res) => {
    try {
        const sql = `
            SELECT 
                DATE_FORMAT(fecha, '%Y-%m-%d') as dia, 
                SUM(total) as total 
            FROM ventas 
            WHERE fecha >= DATE_SUB(NOW(), INTERVAL 7 DAY) 
            GROUP BY dia 
            ORDER BY dia ASC
        `;
        
        const [resultados] = await db.query(sql);

        console.log("--> Datos para gráfica azul:", resultados);
        
        res.json(resultados);

    } catch (error) {
        console.error("--> ERROR en gráfica ventas:", error);
        res.status(500).json({ error: "Error en reporte de ventas" });
    }
});

// === REPORTES: TOP 5 PRODUCTOS MÁS VENDIDOS ===
app.get('/api/reportes/productos-top', verificarToken, async (req, res) => {
    try {
        const sql = `
            SELECT 
                p.nombre, 
                SUM(dv.cantidad) as cantidad_total
            FROM detalle_ventas dv
            JOIN productos p ON dv.producto_id = p.id
            GROUP BY p.id
            ORDER BY cantidad_total DESC
            LIMIT 5
        `;
        const [resultados] = await db.query(sql);
        res.json(resultados);
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: "Error en reporte de productos" });
    }
});

// === REPORTES: DETALLE DE VENTAS DE UN DÍA ESPECÍFICO ===
app.get('/api/reportes/detalle-dia/:fecha', verificarToken, async (req, res) => {
    const { fecha } = req.params; // La fecha viene como YYYY-MM-DD
    
    try {
        const sql = `
            SELECT 
                p.nombre, 
                SUM(dv.cantidad) as cantidad_total,
                SUM(dv.subtotal) as dinero_total
            FROM ventas v
            JOIN detalle_ventas dv ON v.id = dv.venta_id
            JOIN productos p ON dv.producto_id = p.id
            WHERE DATE(v.fecha) = ?
            GROUP BY p.id
            ORDER BY cantidad_total DESC
        `;
        
        const [detalles] = await db.query(sql, [fecha]);
        res.json(detalles);

    } catch (error) {
        console.error(error);
        res.status(500).json({ error: "Error obteniendo detalles del día" });
    }
});

// === VER HISTORIAL DE MOVIMIENTOS ===
app.get('/api/historial', verificarToken, soloAdmin, async (req, res) => {
    try {
        // Traer los últimos 50 movimientos
        const [logs] = await db.query('SELECT * FROM historial ORDER BY fecha DESC LIMIT 50');
        res.json(logs);
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: "Error al obtener historial" });
    }
});

// === GENERAR PEDIDO (CLIENTE) ===
app.post('/api/pedidos', verificarToken, async (req, res) => {
    const { carrito, total } = req.body;
    const clienteId = req.usuario.id;

    if (!carrito || carrito.length === 0) return res.status(400).json({ error: "Carrito vacío" });

    const connection = await db.getConnection();
    try {
        await connection.beginTransaction();

        const [result] = await connection.query(
            'INSERT INTO pedidos (cliente_id, total) VALUES (?, ?)',
            [clienteId, total]
        );
        const pedidoId = result.insertId;

        for (const item of carrito) {
            await connection.query(
                'INSERT INTO detalle_pedidos (pedido_id, producto_id, cantidad, precio_unitario, subtotal) VALUES (?, ?, ?, ?, ?)',
                [pedidoId, item.id, item.cantidad, item.precio, (item.precio * item.cantidad)]
            );

            
            await connection.query(
                'UPDATE productos SET stock_actual = stock_actual - ? WHERE id = ?',
                [item.cantidad, item.id]
            );
        }

        await connection.commit();
        connection.release();
        res.json({ message: "¡Pedido realizado! Pasa a recogerlo a la sucursal.", pedidoId });

    } catch (error) {
        await connection.rollback();
        connection.release();
        console.error(error);
        res.status(500).json({ error: "Error al generar pedido" });
    }
});

// Iniciar el servidor
app.listen(3000, () => {
  console.log('Servidor corriendo en http://localhost:3000');
});