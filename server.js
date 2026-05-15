require('dotenv').config();

const { MercadoPagoConfig, PreApproval } = require('mercadopago');

const express     = require('express');
const cors        = require('cors');
const helmet      = require('helmet');
const rateLimit   = require('express-rate-limit');
const jwt         = require('jsonwebtoken');
const bcrypt      = require('bcryptjs');
const Anthropic   = require('@anthropic-ai/sdk');
const { Pool }    = require('pg');

const app = express();

const JWT_SECRET        = process.env.JWT_SECRET;
const ANTHROPIC_API_KEY = process.env.ANTHROPIC_API_KEY;
const DATABASE_URL      = process.env.DATABASE_URL;
const PORT              = process.env.PORT || 3000;
const FRONTEND_URL      = process.env.FRONTEND_URL || 'https://filipi0805.github.io';

if (!JWT_SECRET)        console.error('JWT_SECRET nao definido!');
if (!ANTHROPIC_API_KEY) console.error('ANTHROPIC_API_KEY nao definido!');
if (!DATABASE_URL)      console.error('DATABASE_URL nao definido!');

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

const initDB = async () => {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS usuarios (
      id        BIGSERIAL PRIMARY KEY,
      nome      TEXT NOT NULL,
      email     TEXT UNIQUE NOT NULL,
      hash      TEXT NOT NULL,
      criado_em TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS consorcios_dados (
      usuario_id BIGINT PRIMARY KEY REFERENCES usuarios(id) ON DELETE CASCADE,
      dados      JSONB NOT NULL DEFAULT '[]',
      atualizado TIMESTAMPTZ DEFAULT NOW()
    );
  `);
  console.log('Banco de dados pronto.');
};

app.use(helmet());
app.use(cors({
  origin: ['https://filipi0805.github.io', 'http://localhost:3000', 'http://127.0.0.1:5500'],
  methods: ['GET','POST','OPTIONS'],
  allowedHeaders: ['Content-Type','Authorization']
}));
app.use(express.json({ limit: '30mb' }));

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, max: 10,
  message: { erro: 'Muitas tentativas. Aguarde 15 minutos.' }
});
const cadastroLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, max: 5,
  message: { erro: 'Muitos cadastros deste IP. Aguarde uma hora.' }
});
const iaLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, max: 30,
  message: { error: { message: 'Limite de analises atingido. Aguarde uma hora.' } }
});

const autenticar = (req, res, next) => {
  const auth = req.headers.authorization;
  if (!auth?.startsWith('Bearer ')) return res.status(401).json({ erro: 'Token nao fornecido.' });
  try { req.user = jwt.verify(auth.slice(7), JWT_SECRET); next(); }
  catch { res.status(401).json({ erro: 'Token invalido ou expirado.' }); }
};

app.get('/', (req, res) => res.json({ status: 'ok', app: 'SmartCota Backend' }));

app.post('/auth/registro', cadastroLimiter, async (req, res) => {
  const { nome, email, senha } = req.body || {};
  if (!nome || !email || !senha) return res.status(400).json({ erro: 'Preencha todos os campos.' });
  if (senha.length < 6) return res.status(400).json({ erro: 'Senha deve ter pelo menos 6 caracteres.' });
  const emailLimpo = email.trim().toLowerCase();
  try {
    const existe = await pool.query('SELECT id FROM usuarios WHERE email=$1', [emailLimpo]);
    if (existe.rows.length) return res.status(400).json({ erro: 'Email ja cadastrado.' });
    const hash = await bcrypt.hash(senha, 12);
    const r = await pool.query(
      'INSERT INTO usuarios (nome,email,hash) VALUES ($1,$2,$3) RETURNING id,nome,email',
      [nome.trim(), emailLimpo, hash]
    );
    const u = r.rows[0];
    await pool.query(
      'INSERT INTO consorcios_dados (usuario_id,dados) VALUES ($1,$2) ON CONFLICT DO NOTHING',
      [u.id, '[]']
    );
    const token = jwt.sign({ id:u.id, nome:u.nome, email:u.email }, JWT_SECRET, { expiresIn:'30d' });
    res.json({ token, usuario: { id:u.id, nome:u.nome, email:u.email } });
  } catch(err) {
    console.error('[Cadastro]', err.message);
    res.status(500).json({ erro: 'Erro ao criar conta.' });
  }
});

app.post('/auth/login', loginLimiter, async (req, res) => {
  const { email, senha } = req.body || {};
  if (!email || !senha) return res.status(400).json({ erro: 'Preencha email e senha.' });
  try {
    const r = await pool.query('SELECT * FROM usuarios WHERE email=$1', [email.trim().toLowerCase()]);
    const u = r.rows[0];
    if (!u) return res.status(401).json({ erro: 'Email ou senha incorretos.' });
    const ok = await bcrypt.compare(senha, u.hash);
    if (!ok) return res.status(401).json({ erro: 'Email ou senha incorretos.' });
    const token = jwt.sign({ id:u.id, nome:u.nome, email:u.email }, JWT_SECRET, { expiresIn:'30d' });
    res.json({ token, usuario: { id:u.id, nome:u.nome, email:u.email } });
  } catch(err) {
    console.error('[Login]', err.message);
    res.status(500).json({ erro: 'Erro ao fazer login.' });
  }
});

app.get('/consorcios', autenticar, async (req, res) => {
  try {
    const r = await pool.query('SELECT dados FROM consorcios_dados WHERE usuario_id=$1', [req.user.id]);
    res.json(r.rows[0]?.dados || []);
  } catch(err) {
    console.error('[GET consorcios]', err.message);
    res.status(500).json({ erro: 'Erro ao buscar dados.' });
  }
});

app.post('/consorcios', autenticar, async (req, res) => {
  const lista = req.body?.dados;
  if (!Array.isArray(lista)) return res.status(400).json({ erro: 'Dados invalidos.' });
  try {
    await pool.query(`
      INSERT INTO consorcios_dados (usuario_id,dados,atualizado)
      VALUES ($1,$2,NOW())
      ON CONFLICT (usuario_id) DO UPDATE SET dados=$2, atualizado=NOW()
    `, [req.user.id, JSON.stringify(lista)]);
    res.json({ ok: true });
  } catch(err) {
    console.error('[POST consorcios]', err.message);
    res.status(500).json({ erro: 'Erro ao salvar dados.' });
  }
});

app.post('/ia/analisar', autenticar, iaLimiter, async (req, res) => {
  if (!ANTHROPIC_API_KEY)
    return res.status(500).json({ error: { message: 'Chave da API nao configurada.' } });
  const { messages } = req.body || {};
  if (!messages?.length) return res.status(400).json({ error: { message: 'Nenhuma mensagem.' } });
  try {
    const client = new Anthropic({ apiKey: process.env.ANTHROPIC_API_KEY });
    const response = await client.messages.create({ model: 'claude-haiku-4-5', max_tokens:4096, messages });
    res.json(response);
  } catch(err) {
    console.error('[IA]', err.message);
    const status = err.status || 500;
    let msg = err.message || 'Erro ao chamar a IA.';
    if (status === 401) msg = 'Chave API invalida.';
    if (status === 429) msg = 'Limite atingido. Aguarde.';
    res.status(status).json({ error: { message: msg } });
  }
});
// ══ MERCADO PAGO - ASSINATURA ══
const mp = new MercadoPagoConfig({ 
  accessToken: process.env.MP_ACCESS_TOKEN 
});

app.post('/assinatura/criar', autenticar, async (req, res) => {
  try {
    const { email } = req.user;
    const preApproval = new PreApproval(mp);
    const resultado = await preApproval.create({
      body: {
        reason: 'SmartCota Mensal',
        auto_recurring: {
          frequency: 1,
          frequency_type: 'months',
          transaction_amount: 89.90,
          currency_id: 'BRL'
        },
        payer_email: email,
        back_url: 'https://filipi0805.github.io/smartcota-app/',
        status: 'pending'
      }
    });
    res.json({ url: resultado.init_point });
  } catch(err) {
    console.error('[MP]', err.message);
    res.status(500).json({ erro: 'Erro ao criar assinatura.' });
  }
});
initDB().then(() => {
  app.listen(PORT, () => {
    console.log(`SmartCota backend na porta ${PORT}`);
    console.log(`JWT_SECRET: ${JWT_SECRET ? 'OK' : 'FALTANDO'}`);
    console.log(`ANTHROPIC:  ${ANTHROPIC_API_KEY ? 'OK' : 'FALTANDO'}`);
    console.log(`DATABASE:   ${DATABASE_URL ? 'OK' : 'FALTANDO'}`);
    console.log(`CORS:       ${FRONTEND_URL}`);
  });
}).catch(err => { console.error('Erro no banco:', err.message); process.exit(1); });