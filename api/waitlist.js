const fs = require('fs');

module.exports = async (req, res) => {
  if (req.method !== 'POST') return res.status(405).end();
  const { email } = req.body || {};
  if (!email || !email.includes('@')) return res.status(400).json({ error: 'valid email required' });
  try {
    const entry = `${new Date().toISOString()} ${email}\n`;
    fs.appendFileSync('/var/bastion/waitlist.txt', entry, 'utf-8');
    res.status(200).json({ ok: true });
  } catch (e) {
    console.error('waitlist write failed:', e.message);
    res.status(500).json({ error: 'storage error' });
  }
};
