import { neon } from '@neondatabase/serverless';

export default async function handler(req, res) {
  res.setHeader('Cache-Control', 'no-store');

  if (req.method !== 'GET') {
    res.setHeader('Allow', 'GET');

    return res.status(405).json({
      error: 'Método no permitido.'
    });
  }

  try {
    if (!process.env.DATABASE_URL) {
      throw new Error('Falta DATABASE_URL.');
    }

    const sql = neon(process.env.DATABASE_URL);

    const items = await sql`
      SELECT
        product_key,
        status
      FROM product_availability
      ORDER BY product_key
    `;

    return res.status(200).json({
      items
    });

  } catch (error) {
    console.error(error);

    return res.status(500).json({
      error: 'No se pudo consultar disponibilidad.'
    });
  }
}
