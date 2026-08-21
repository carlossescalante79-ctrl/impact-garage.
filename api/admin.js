import crypto from 'node:crypto';
import { neon } from '@neondatabase/serverless';

const COOKIE_NAME = 'impact_admin';
const MAX_AGE = 60 * 60 * 12;

function sql() {
  if (!process.env.DATABASE_URL) {
    throw new Error('Falta DATABASE_URL en Vercel.');
  }

  return neon(process.env.DATABASE_URL);
}

function getSecret() {
  if (!process.env.SESSION_SECRET) {
    throw new Error('Falta SESSION_SECRET en Vercel.');
  }

  return process.env.SESSION_SECRET;
}

function sign(value) {
  return crypto
    .createHmac('sha256', getSecret())
    .update(value)
    .digest('hex');
}

function makeCookie(username) {
  const expires = Date.now() + MAX_AGE * 1000;

  const payload = Buffer.from(
    JSON.stringify({
      username,
      expires
    })
  ).toString('base64url');

  const token = `${payload}.${sign(payload)}`;

  return `${COOKIE_NAME}=${token}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${MAX_AGE}`;
}

function clearCookie() {
  return `${COOKIE_NAME}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`;
}

function getCookies(req) {
  const raw = req.headers.cookie || '';

  return Object.fromEntries(
    raw
      .split(';')
      .filter(Boolean)
      .map(part => {
        const index = part.indexOf('=');

        return [
          part.slice(0, index).trim(),
          part.slice(index + 1).trim()
        ];
      })
  );
}

function getSession(req) {
  try {
    const token = getCookies(req)[COOKIE_NAME];

    if (!token) return null;

    const [payload, signature] = token.split('.');

    if (!payload || !signature) return null;

    const expected = sign(payload);

    const a = Buffer.from(signature);
    const b = Buffer.from(expected);

    if (
      a.length !== b.length ||
      !crypto.timingSafeEqual(a, b)
    ) {
      return null;
    }

    const data = JSON.parse(
      Buffer.from(payload, 'base64url').toString('utf8')
    );

    if (!data.expires || Date.now() > data.expires) {
      return null;
    }

    return data;
  } catch {
    return null;
  }
}

function safeEqual(a = '', b = '') {
  const aa = Buffer.from(String(a));
  const bb = Buffer.from(String(b));

  if (aa.length !== bb.length) return false;

  return crypto.timingSafeEqual(aa, bb);
}

async function getBody(req) {
  if (typeof req.body === 'object' && req.body !== null) {
    return req.body;
  }

  if (typeof req.body === 'string') {
    try {
      return JSON.parse(req.body);
    } catch {
      return {};
    }
  }

  return {};
}

export default async function handler(req, res) {
  res.setHeader('Cache-Control', 'no-store');

  try {
    if (req.method === 'GET') {
      const session = getSession(req);

      if (!session) {
        return res.status(401).json({
          authenticated: false
        });
      }

      const db = sql();

      const items = await db`
        SELECT
          product_key,
          label,
          category,
          status,
          updated_at
        FROM product_availability
        ORDER BY category, label
      `;

      return res.status(200).json({
        authenticated: true,
        items
      });
    }

    if (req.method === 'POST') {
      const body = await getBody(req);

      if (body.action === 'login') {
        const expectedUser = process.env.ADMIN_USER;
        const expectedPassword = process.env.ADMIN_PASSWORD;

        if (!expectedUser || !expectedPassword) {
          return res.status(500).json({
            error: 'Falta configurar ADMIN_USER o ADMIN_PASSWORD en Vercel.'
          });
        }

        if (
          !safeEqual(body.username, expectedUser) ||
          !safeEqual(body.password, expectedPassword)
        ) {
          return res.status(401).json({
            error: 'Usuario o contraseña incorrectos.'
          });
        }

        res.setHeader(
          'Set-Cookie',
          makeCookie(expectedUser)
        );

        return res.status(200).json({
          ok: true
        });
      }

      if (body.action === 'logout') {
        res.setHeader(
          'Set-Cookie',
          clearCookie()
        );

        return res.status(200).json({
          ok: true
        });
      }

      const session = getSession(req);

      if (!session) {
        return res.status(401).json({
          error: 'No autorizado.'
        });
      }

      if (body.action === 'update') {
        const productKey = String(body.productKey || '').trim();
        const label = String(body.label || '').trim();
        const category = String(body.category || '').trim();
        const status = String(body.status || '').trim();

        const validStatuses = [
          'available',
          'soldout',
          'hidden'
        ];

        if (
          !productKey ||
          !label ||
          !category ||
          !validStatuses.includes(status)
        ) {
          return res.status(400).json({
            error: 'Datos inválidos.'
          });
        }

        const db = sql();

        const rows = await db`
          INSERT INTO product_availability (
            product_key,
            label,
            category,
            status,
            updated_at
          )
          VALUES (
            ${productKey},
            ${label},
            ${category},
            ${status},
            NOW()
          )

          ON CONFLICT (product_key)

          DO UPDATE SET
            label = EXCLUDED.label,
            category = EXCLUDED.category,
            status = EXCLUDED.status,
            updated_at = NOW()

          RETURNING
            product_key,
            label,
            category,
            status,
            updated_at
        `;

        return res.status(200).json({
          ok: true,
          item: rows[0]
        });
      }

      return res.status(400).json({
        error: 'Acción no reconocida.'
      });
    }

    res.setHeader(
      'Allow',
      'GET, POST'
    );

    return res.status(405).json({
      error: 'Método no permitido.'
    });
  } catch (error) {
    console.error(error);

    return res.status(500).json({
      error: error.message || 'Error interno.'
    });
  }
}
