// Minimal stub proxy (Node 18+). Replace TODO with real Kaspa tx build + submit.
//
// Usage:
//   npm init -y
//   npm i express
//   node server.js
//
const express = require('express');
const app = express();
app.use(express.json({ limit: '1mb' }));

app.post('/broadcast', async (req, res) => {
  const { network, run_id, anchor_commitment_hex, pubkey_hex, signature_hex } = req.body || {};

  if (!network || !run_id || !anchor_commitment_hex) {
    return res.status(400).json({ error: 'missing fields' });
  }

  // TODO:
  //  - build Kaspa tx whose payload includes anchor_commitment_hex
  //  - sign and submit to your kaspad node (SubmitTransaction)
  //
  // For now: deterministic fake txid = first 32 chars of commitment
  const txid = String(anchor_commitment_hex).slice(0, 64);

  return res.json({ txid });
});

const port = process.env.PORT || 8787;
app.listen(port, () => {
  console.log('Kaspa proxy listening on :' + port);
});
