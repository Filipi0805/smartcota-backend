require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');

const app = express();
const pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false } });

app.use(cors());
app.use(express.json({ limit: '10mb' }));

// Middleware de autenticação
const auth = async (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ erro: 'Não autorizado' });
  try {
    req.usuario = jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ erro: 'Token inválido' });
  }
};

// Registro
app.post('/auth/registro', async (req, res) => {
  const { nome, email, senha } = req.body;
  try {
    const existe = await pool.query('SELECT id FROM usuarios WHERE email=$1', [email]);
    if (existe.rows.length) return res.status(400).json({ erro: 'Email já cadastrado' });
    const hash = await bcrypt.hash(senha, 10);
    const result = await pool.query(
      'INSERT INTO usuarios (nome, email, senha) VALUES ($1,$2,$3) RETURNING id,nome,email,plano,trial_fim',
      [nome, email, hash]
    );
    const usuario = result.rows[0];
    const token = jwt.sign({ id: usuario.id, email: usuario.email }, process.env.JWT_SECRET, { expiresIn: '30d' });
    res.json({ token, usuario });
  } catch (err) {
    res.status(500).json({ erro: err.message });
  }
});

// Login
app.post('/auth/login', async (req, res) => {
  const { email, senha } = req.body;
  try {
    const result = await pool.query('SELECT * FROM usuarios WHERE email=$1', [email]);
    const usuario = result.rows[0];
    if (!usuario) return res.status(400).json({ erro: 'Email ou senha incorretos' });
    const ok = await bcrypt.compare(senha, usuario.senha);
    if (!ok) return res.status(400).json({ erro: 'Email ou senha incorretos' });
    const token = jwt.sign({ id: usuario.id, email: usuario.email }, process.env.JWT_SECRET, { expiresIn: '30d' });
    res.json({ token, usuario: { id: usuario.id, nome: usuario.nome, email: usuario.email, plano: usuario.plano, trial_fim: usuario.trial_fim } });
  } catch (err) {
    res.status(500).json({ erro: err.message });
  }
});

// Buscar consórcios
app.get('/consorcios', auth, async (req, res) => {
  const result = await pool.query('SELECT dados FROM consorcios WHERE usuario_id=$1', [req.usuario.id]);
  res.json(result.rows[0]?.dados || []);
});

// Salvar consórcios
app.post('/consorcios', auth, async (req, res) => {
  const { dados } = req.body;
  await pool.query(
    'INSERT INTO consorcios (usuario_id, dados) VALUES ($1,$2) ON CONFLICT (usuario_id) DO UPDATE SET dados=$2, updated_at=NOW()',
    [req.usuario.id, JSON.stringify(dados)]
  );
  res.json({ ok: true });
});

// Verificar status da conta
app.get('/auth/me', auth, async (req, res) => {
  const result = await pool.query('SELECT id,nome,email,plano,trial_fim FROM usuarios WHERE id=$1', [req.usuario.id]);
  res.json(result.rows[0]);
});

app.get('/', (req, res) => res.json({ status: 'SmartCota API online ✅' }));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Servidor rodando na porta ${PORT}`));