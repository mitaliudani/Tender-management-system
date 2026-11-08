import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync, mkdtempSync, mkdirSync, rmSync, writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {resolve, join} from 'node:path';
import {scanJsp, scanRepository, findingKey, compareBaseline} from './scan.mjs';

const repo = resolve(import.meta.dirname, '..');

test('flags the four documented source-level risk patterns', () => {
  const source = `if(!user.equalsIgnoreCase("admin")){ }\n` +
    `session.getAttribute("password");\n` +
    `<%=request.getParameter("vid")%>\n` +
    `<a href="RemoveNoticeSrv?noticeid=7">Remove</a>`;
  assert.deepEqual(new Set(scanJsp(source, 'example.jsp').map(f => f.id)),
    new Set(['AUTH-001', 'AUTH-002', 'XSS-001', 'CSRF-001']));
});

test('does not flag the corrected role guard or ordinary public links', () => {
  const safe = `if(!"admin".equalsIgnoreCase(user)) { response.sendError(403); return; }\n` +
    `<a href="viewTender.jsp">View tender</a>`;
  assert.equal(scanJsp(safe, 'example.jsp').length, 0);
});

test('detects role comparison variants and prefixed or scripted GET actions', () => {
  const source = `if (role.equals("admin")) { }\n` +
    `<a href="./RemoveNoticeSrv?noticeid=3">Delete</a>\n` +
    `window.location = '/app/AcceptBidSrv?bid=8';\n` +
    `<form action="../RejectBidSrv?bid=2" method="get"></form>`;
  const findings = scanJsp(source, 'test.jsp');
  assert.equal(findings.filter(f => f.id === 'AUTH-001').length, 1);
  assert.equal(findings.filter(f => f.id === 'CSRF-001').length, 3);
});

test('recursively scans nested JSP files and ignores build/vendor directories', () => {
  const root = mkdtempSync(join(tmpdir(), 'tender-scan-'));
  try {
    mkdirSync(resolve(root, 'admin'));
    mkdirSync(resolve(root, 'node_modules'));
    writeFileSync(resolve(root, 'admin', 'unsafe.jsp'), `role.equals("admin")`);
    writeFileSync(resolve(root, 'node_modules', 'ignored.jsp'), `role.equals("admin")`);
    const findings = scanRepository(root);
    assert.equal(findings.length, 1);
    assert.equal(findings[0].path, 'admin/unsafe.jsp');
  } finally {
    rmSync(root, {recursive: true, force: true});
  }
});

test('every access-controlled JSP rejects missing sessions and stops rendering', () => {
  const admin = ['addNotice', 'adminHome', 'adminViewVendor', 'adminViewVendorDetail',
    'createTender', 'removeNotice', 'searchTender', 'updateNotice', 'updateNoticeForm',
    'viewAssignedTenders', 'viewNotice', 'viewTender', 'viewTenderBids', 'viewTenderBidsForm'];
  const vendor = ['bidHistory', 'bidTender', 'bidTenderForm', 'updatePassword',
    'updateProfile', 'vendorHome', 'vendorSearchTender', 'vendorViewTender', 'viewProfile'];
  for (const [role, pages] of [['admin', admin], ['user', vendor]]) {
    for (const page of pages) {
      const source = readFileSync(resolve(repo, `${page}.jsp`), 'utf8');
      const scriptlets = [...source.matchAll(/<%(?!@)([\s\S]*?)%>/g)]
        .map(match => match[1].replace(/\/\*[\s\S]*?\*\/|\/\/[^\n]*/g, ''));
      const guardPattern = new RegExp(
        `if\\s*\\(\\s*!"${role}"\\.equalsIgnoreCase\\(user\\)\\s*\\|\\|\\s*` +
        `uname\\s*==\\s*null\\s*\\|\\|\\s*uname\\.trim\\(\\)\\.isEmpty\\(\\)\\s*\\)` +
        `\\s*\\{\\s*response\\.sendRedirect\\("loginFailed\\.jsp"\\);\\s*return;`);
      assert.ok(scriptlets.some(scriptlet => guardPattern.test(scriptlet)),
        `${page} must have an active ordered guard, redirect and early return`);
      assert.doesNotMatch(source, /session\.getAttribute\("password"\)|\bpword\b/, page);
    }
  }
});

test('baseline compares stable rule, path and evidence rather than line numbers', () => {
  const baseline = JSON.parse(readFileSync(resolve(repo, 'security/baseline.json'), 'utf8'));
  const findings = scanRepository(repo);
  const comparison = compareBaseline(findings, baseline);
  assert.equal(comparison.newFindings.length, 0, `Unexpected findings: ${comparison.newFindings.map(findingKey)}`);
  assert.equal(findings.length, 0, 'All tracked source signatures should be removed');
});
