const express  = require('express');
const cors     = require('cors');
const jwt      = require('jsonwebtoken');
const bcrypt   = require('bcryptjs');
const Anthropic = require('@anthropic-ai/sdk');
const fs       = require('fs');
const path     = require('path');

const app = express();
app.use(cors());
app.use(express.json({ limit: '30mb' })); // imagens podem ser grandes

// ── Variáveis de ambiente ────────────────────────────────────────────────
const JWT_SECRET       = process.env.JWT_SECRET       || 'smartcota-chave-secreta-2024';
const ANTHROPIC_API_KEY = process.env.ANTHROPIC_API_KEY; // configurar no Render
const PORT             = process.env.PORT              || 3000;

// ── Persistência simples em arquivo (sobrevive a deploys no Render) ───────
const DATA_FILE = path.join('/tmp', 'smartcota_data.json');

const carregarDados = () => {
  try {
    if (fs.existsSync(DATA_FILE)) return JSON.parse(fs.readFileSync(DATA_FILE, 'utf8'));
  } catch {}
  return { users: [], dados: {} };
};

const salvarDados = (db) => {
  try { fs.writeFileSync(DATA_FILE, JSON.stringify(db)); } catch {}
};

let db = carregarDados();
// db.users  → [ {id, nome, email, hash} ]
// db.dados  → { userId: [ ...consorcios ] }

// ── Middleware de autenticação ─────────────────────────────────────────────
const autenticar = (req, res, next) => {
  const auth = req.headers.authorization;
  if (!auth?.startsWith('Bearer '))
    return res.status(401).json({ erro: 'Token não fornecido.' });
  try {
    req.user = jwt.verify(auth.slice(7), JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ erro: 'Token inválido ou expirado.' });
  }
};

// ── Health check ───────────────────────────────────────────────────────────
app.get('/', (req, res) => res.json({ status: 'ok', app: 'SmartCota Backend' }));

// ── AUTH: Cadastro ─────────────────────────────────────────────────────────
app.post('/auth/registro', async (req, res) => {
  const { nome, email, senha } = req.body || {};
  if (!nome || !email || !senha)
    return res.status(400).json({ erro: 'Preencha nome, email e senha.' });
  if (senha.length < 6)
    return res.status(400).json({ erro: 'Senha deve ter pelo menos 6 caracteres.' });
  if (db.users.find(u => u.email === email))
    return res.status(400).json({ erro: 'Email já cadastrado.' });

  const hash = await bcrypt.hash(senha, 10);
  const usuario = { id: Date.now(), nome: nome.trim(), email: email.trim().toLowerCase(), hash };
  db.users.push(usuario);
  salvarDados(db);

  const token = jwt.sign({ id: usuario.id, nome: usuario.nome, email: usuario.email }, JWT_SECRET, { expiresIn: '30d' });
  res.json({ token, usuario: { id: usuario.id, nome: usuario.nome, email: usuario.email } });
});

// ── AUTH: Login ────────────────────────────────────────────────────────────
app.post('/auth/login', async (req, res) => {
  const { email, senha } = req.body || {};
  if (!email || !senha)
    return res.status(400).json({ erro: 'Preencha email e senha.' });

  const u = db.users.find(x => x.email === email.trim().toLowerCase());
  if (!u) return res.status(401).json({ erro: 'Email ou senha incorretos.' });

  const ok = await bcrypt.compare(senha, u.hash);
  if (!ok) return res.status(401).json({ erro: 'Email ou senha incorretos.' });

  const token = jwt.sign({ id: u.id, nome: u.nome, email: u.email }, JWT_SECRET, { expiresIn: '30d' });
  res.json({ token, usuario: { id: u.id, nome: u.nome, email: u.email } });
});

// ── CONSÓRCIOS: Buscar ─────────────────────────────────────────────────────
app.get('/consorcios', autenticar, (req, res) => {
  res.json(db.dados[req.user.id] || []);
});

// ── CONSÓRCIOS: Salvar ─────────────────────────────────────────────────────
app.post('/consorcios', autenticar, (req, res) => {
  const lista = req.body?.dados;
  if (!Array.isArray(lista))
    return res.status(400).json({ erro: 'Dados inválidos.' });
  db.dados[req.user.id] = lista;
  salvarDados(db);
  res.json({ ok: true });
});

// ── IA: Analisar documento ─────────────────────────────────────────────────
app.post('/ia/analisar', autenticar, async (req, res) => {
  if (!ANTHROPIC_API_KEY) {
    return res.status(500).json({
      error: { message: 'Chave da API Anthropic não configurada no servidor. Adicione ANTHROPIC_API_KEY nas variáveis de ambiente do Render.' }
    });
  }

  const { messages } = req.body || {};
  if (!messages?.length)
    return res.status(400).json({ error: { message: 'Nenhuma mensagem enviada.' } });

  try {
    const client = new Anthropic({ apiKey: ANTHROPIC_API_KEY });

    const response = await client.messages.create({
      model:      'claude-sonnet-4-5',   // suporta visão (imagens + PDFs)
      max_tokens: 4096,
      messages
    });

    res.json(response);

  } catch (err) {
    console.error('[IA] Erro:', err.message);
    const status = err.status || 500;
    let msg = err.message || 'Erro ao chamar a IA.';

    if (status === 401) msg = 'Chave API inválida. Verifique ANTHROPIC_API_KEY no Render.';
    if (status === 429) msg = 'Limite de requisições atingido. Aguarde alguns segundos e tente novamente.';
    if (status === 529) msg = 'Serviço da IA sobrecarregado. Tente novamente em instantes.';

    res.status(status).json({ error: { message: msg } });
  }
});

// ── Start ──────────────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`✅ SmartCota backend rodando na porta ${PORT}`);
  console.log(`   ANTHROPIC_API_KEY: ${ANTHROPIC_API_KEY ? '✓ configurada' : '✗ NÃO CONFIGURADA'}`);
});