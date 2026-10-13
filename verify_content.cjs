const fs = require('fs');
const ct = fs.readFileSync('dist/assets/content.ts-uYP3nYcy.js', 'utf8');

const checks = [
  ['MutationObserver',        ct.includes('MutationObserver')],
  ['requestAnimationFrame',   ct.includes('requestAnimationFrame')],
  ['data-sentinel-hidden',    ct.includes('data-sentinel-hidden')],
  ['adBlockingEnabled',       ct.includes('adBlockingEnabled')],
  ['adBlockAllowlist',        ct.includes('adBlockAllowlist')],
  ['storage.onChanged',       ct.includes('onChanged')],
  ['ins.adsbygoogle',         ct.includes('adsbygoogle')],
  ['div-gpt-ad',              ct.includes('div-gpt-ad')],
  ['display:none present',    ct.includes('display')],
  ['No broad class*=ad',      !ct.includes('class*="ad"') && !ct.includes("class*='ad'") && !ct.includes('[id*="banner"]')],
];
console.log('Content script verification:');
let allPass = true;
checks.forEach(function(pair) {
  const name = pair[0], pass = pair[1];
  console.log((pass ? '  PASS' : '  FAIL') + '  ' + name);
  if (!pass) allPass = false;
});
console.log('');
console.log('Overall: ' + (allPass ? 'ALL PASS' : 'FAILURES DETECTED'));
console.log('File size: ' + ct.length + ' bytes');
