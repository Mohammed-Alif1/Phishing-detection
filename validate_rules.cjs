const fs = require('fs');
const rules = JSON.parse(fs.readFileSync('public/rules/adblock_rules.json', 'utf8'));

const VALID_RESOURCE_TYPES = new Set([
  'main_frame','sub_frame','stylesheet','script','image','font','object',
  'xmlhttprequest','ping','csp_report','media','websocket','webtransport',
  'webbundle','other'
]);
const VALID_ACTION_TYPES = new Set(['block','redirect','allow','upgradeScheme','modifyHeaders','allowAllRequests']);

const DANGEROUS_BROAD = ['||google.com^','||facebook.com^','||twitter.com^','||linkedin.com^','||amazon.com^','||microsoft.com^','||apple.com^'];

let errors = [];
let warnings = [];
const ids = new Set();
const urlFilters = new Set();
const domains = [];

rules.forEach((rule, i) => {
  const pos = 'id=' + rule.id + ' (index ' + i + ')';
  
  if (ids.has(rule.id)) errors.push('Duplicate ID: ' + rule.id);
  ids.add(rule.id);
  
  if (rule.id !== i + 1) warnings.push('Non-sequential ' + pos);
  
  if (!VALID_ACTION_TYPES.has(rule.action.type))
    errors.push('Invalid action at ' + pos + ': ' + rule.action.type);
  
  const cond = rule.condition;
  if (!cond.urlFilter && !cond.regexFilter)
    errors.push('No filter at ' + pos);
  
  if (cond.resourceTypes) {
    cond.resourceTypes.forEach(rt => {
      if (!VALID_RESOURCE_TYPES.has(rt))
        errors.push('Invalid resourceType [' + rt + '] at ' + pos);
    });
  }
  
  if (cond.urlFilter) {
    if (urlFilters.has(cond.urlFilter))
      warnings.push('Duplicate urlFilter at ' + pos + ': ' + cond.urlFilter);
    urlFilters.add(cond.urlFilter);
    
    if (DANGEROUS_BROAD.includes(cond.urlFilter))
      errors.push('DANGEROUS broad rule at ' + pos + ': ' + cond.urlFilter);
    
    const m = cond.urlFilter.match(/^\|\|([^/^*]+)\^/);
    if (m) domains.push({ id: rule.id, domain: m[1] });
  }
  
  if (!rule.priority || rule.priority < 1)
    errors.push('Invalid priority at ' + pos);
});

console.log('RULE VALIDATION REPORT');
console.log('======================');
console.log('Total rules:         ' + rules.length);
console.log('Unique IDs:          ' + ids.size);
console.log('Unique urlFilters:   ' + urlFilters.size);
console.log('Domains extracted:   ' + domains.length);
console.log('All action=block:    ' + rules.every(r => r.action.type === 'block'));
console.log('');

if (errors.length === 0) {
  console.log('ERRORS: none');
} else {
  console.log('ERRORS (' + errors.length + '):');
  errors.forEach(e => console.log('  ERROR: ' + e));
}
console.log('');

if (warnings.length === 0) {
  console.log('WARNINGS: none');
} else {
  console.log('WARNINGS (' + warnings.length + '):');
  warnings.forEach(w => console.log('  WARN: ' + w));
}
console.log('');

console.log('Resource type coverage:');
const rtCounts = {};
rules.forEach(r => (r.condition.resourceTypes || []).forEach(rt => { rtCounts[rt] = (rtCounts[rt]||0)+1; }));
Object.entries(rtCounts).sort((a,b) => b[1]-a[1]).forEach(([k,v]) => console.log('  ' + k.padEnd(20) + v));

console.log('');
console.log('Sample domains (first 20):');
domains.slice(0,20).forEach(d => console.log('  id=' + String(d.id).padStart(3) + '  ' + d.domain));

// Specific checks
const aolRule = rules.find(r => r.condition.urlFilter && r.condition.urlFilter.includes('aol.com^'));
if (aolRule) {
  const hasMainFrame = (aolRule.condition.resourceTypes || []).includes('main_frame');
  if (hasMainFrame) warnings.push('aol.com rule includes main_frame - users cannot navigate to aol.com');
  console.log('');
  console.log('aol.com rule (id=' + aolRule.id + ') resourceTypes: ' + JSON.stringify(aolRule.condition.resourceTypes));
  console.log('  main_frame included: ' + hasMainFrame + ' (should be false for ad-only domain used only by publishers)');
}

// Check googletag/gtm - are we blocking GTM entirely?
const gtmRule = rules.find(r => r.condition.urlFilter && r.condition.urlFilter.includes('googletagmanager.com'));
if (gtmRule) {
  console.log('');
  console.log('GTM rule (id=' + gtmRule.id + '): ' + gtmRule.condition.urlFilter);
  console.log('  NOTE: Blocking all of googletagmanager.com will break sites that use GTM for non-ad purposes.');
}

const analyticsRule = rules.find(r => r.condition.urlFilter && r.condition.urlFilter.includes('google-analytics.com'));
if (analyticsRule) {
  console.log('');
  console.log('Google Analytics rule (id=' + analyticsRule.id + '): ' + analyticsRule.condition.urlFilter);
  console.log('  NOTE: Blocking GA is intentional for privacy but may break some site functionality.');
}

console.log('');
console.log('OVERALL: ' + (errors.length === 0 ? 'PASS' : 'FAIL - ' + errors.length + ' errors'));
