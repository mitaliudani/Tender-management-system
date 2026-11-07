/**
 * Read-only source scanner for the legacy Tender Management System JSP files.
 * This is a regression aid, NOT a dynamic penetration test or security audit.
 */
import {readFileSync, readdirSync} from 'node:fs';
import {resolve, basename} from 'node:path';
import {fileURLToPath} from 'node:url';

export const RULES = Object.freeze([
  {
    id: 'AUTH-001', severity: 'medium', title: 'Null-unsafe role comparison',
    explanation: 'A missing session role can throw before the authorization redirect.',
    advice: 'Use a null-safe expectedRole.equalsIgnoreCase(user) check and stop rendering after rejection.',
    pattern: /\buser\.equalsIgnoreCase\(\s*["'](?:admin|user)["']\s*\)/g,
  },
  {
    id: 'AUTH-002', severity: 'high', title: 'Session password used for access control',
    explanation: 'Pages read a password value from the session. Passwords should not be retained as authorization state.',
    advice: 'Change the missing login backend to store only an authenticated principal and server-issued role; remove the password session attribute.',
    pattern: /session\.getAttribute\(\s*["']password["']\s*\)/g,
  },
  {
    id: 'XSS-001', severity: 'high', title: 'Unescaped request parameter in HTML',
    explanation: 'A request parameter is directly embedded in the JSP response.',
    advice: 'Encode the value for its HTML context before rendering it.',
    pattern: /<%=\s*request\.getParameter\([\s\S]*?\)\s*%>/g,
  },
  {
    id: 'CSRF-001', severity: 'high', title: 'State-changing servlet linked through GET',
    explanation: 'The link invokes a bid decision or notice removal with GET parameters.',
    advice: 'Use POST with server-verified CSRF tokens and authorization; update the missing servlet implementation.',
    pattern: /href\s*=\s*["'](?:AcceptBidSrv|RejectBidSrv|RemoveNoticeSrv)\?/g,
  },
]);

function snippet(value) {
  return value.replace(/\s+/g, ' ').trim().slice(0, 150);
}

export function scanJsp(source, path) {
  const findings = [];
  for (const rule of RULES) {
    for (const match of source.matchAll(rule.pattern)) {
      const line = source.slice(0, match.index).split('\n').length;
      findings.push({id: rule.id, severity: rule.severity, title: rule.title,
        path, line, snippet: snippet(match[0]), explanation: rule.explanation, advice: rule.advice});
    }
  }
  return findings.sort((a, b) => a.line - b.line || a.id.localeCompare(b.id));
}

export function scanRepository(root) {
  const findings = [];
  for (const path of readdirSync(root).filter(path => path.endsWith('.jsp')).sort()) {
    findings.push(...scanJsp(readFileSync(resolve(root, path), 'utf8'), path));
  }
  return findings;
}

export function findingKey(finding) {
  return `${finding.id}:${finding.path}:${finding.snippet}`;
}

export function compareBaseline(findings, baseline) {
  if (baseline.schemaVersion !== 1 || !Array.isArray(baseline.findings)) throw new Error('Invalid security baseline');
  const known = new Set(baseline.findings);
  const current = new Set(findings.map(findingKey));
  return {
    newFindings: findings.filter(f => !known.has(findingKey(f))),
    resolvedFindings: baseline.findings.filter(key => !current.has(key)),
  };
}

export function toMarkdown(findings, comparison) {
  const counts = Object.fromEntries(RULES.map(r => [r.id, findings.filter(f => f.id === r.id).length]));
  const lines = [
    '# Tender Management System — static security findings', '',
    '> Source inspection only. No running deployment, live account, database, or exploit testing was used.', '',
    `Matched **${findings.length}** occurrences of four tracked JSP signatures. A zero count does not establish overall security.`, '',
    '| Rule | Severity | Current findings |', '| --- | --- | ---: |',
    ...RULES.map(r => `| ${r.id}: ${r.title} | ${r.severity} | ${counts[r.id]} |`), '',
    `New since baseline: **${comparison.newFindings.length}**. Resolved since baseline: **${comparison.resolvedFindings.length}**.`, '',
    '## Findings', '',
    ...(findings.length ? findings.map(f => `- **${f.id} (${f.severity})** — \`${f.path}:${f.line}\`: ${f.title}. ${f.advice}`) : ['No matches for the four configured signatures.']), '',
    '## Limits', '',
    '- A passing regression check only means no new signature matching these rules was introduced.',
    '- Missing Java servlet/DAO source prevents end-to-end authorization, CSRF, password-storage, and database review.',
    '- Review findings manually; static signatures may miss issues or produce false positives.', '',
  ];
  return lines.join('\n');
}

const isCli = process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isCli) {
  const root = resolve(fileURLToPath(new URL('..', import.meta.url)));
  const findings = scanRepository(root);
  const baseline = JSON.parse(readFileSync(resolve(root, 'security/baseline.json'), 'utf8'));
  const comparison = compareBaseline(findings, baseline);
  const format = process.argv.includes('--json') ? 'json' : 'markdown';
  process.stdout.write(format === 'json'
    ? JSON.stringify({findings, ...comparison}, null, 2) + '\n'
    : toMarkdown(findings, comparison));
  if (process.argv.includes('--check') && comparison.newFindings.length) process.exitCode = 1;
}
