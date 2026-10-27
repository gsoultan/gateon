// Copyright (c) 2026 Gembit Soultan Shirazi <gembit.soultan@gmail.com>. All rights reserved.
// SPDX-License-Identifier: MIT

// Renders the PWA icons in ui/public from gateon-logo.svg with the Chromium
// that Playwright installs. Run from ui/: `node scripts/pwa-icons.cjs`.
// The output is committed; this only needs to run when the logo changes.

const { chromium } = require('playwright');
const fs = require('fs');
const svg = fs.readFileSync(__dirname + '/../public/gateon-logo.svg', 'utf8');
const out = __dirname + '/../public/';
(async () => {
  const b = await chromium.launch();
  const page = await b.newPage();
  // [file, canvas size, logo size, background]
  const jobs = [
    ['pwa-192x192.png', 192, 192, 'transparent'],
    ['pwa-512x512.png', 512, 512, 'transparent'],
    ['pwa-512x512-maskable.png', 512, 400, '#1a1b1e'],
    ['apple-touch-icon.png', 180, 180, '#1a1b1e'],
  ];
  for (const [name, size, logo, bg] of jobs) {
    await page.setViewportSize({ width: size, height: size });
    await page.setContent(`<html><body style="margin:0;width:${size}px;height:${size}px;background:${bg};display:flex;align-items:center;justify-content:center"><div style="width:${logo}px;height:${logo}px">${svg.replace(/width="96" height="96"/, 'width="100%" height="100%"')}</div></body></html>`);
    await page.screenshot({ path: out + name, omitBackground: bg === 'transparent' });
    console.log('wrote', name);
  }
  await b.close();
})();
