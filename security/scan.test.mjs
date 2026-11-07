import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {resolve} from 'node:path';
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

test('every access-controlled JSP rejects missing sessions and stops rendering', () => {
  const admin = ['addNotice', 'adminHome', 'adminViewVendor', 'adminViewVendorDetail',
    'createTender', 'removeNotice', 'searchTender', 'updateNotice', 'updateNoticeForm',
    'viewAssignedTenders', 'viewNotice', 'viewTender', 'viewTenderBids', 'viewTenderBidsForm'];
  const vendor = ['bidHistory', 'bidTender', 'bidTenderForm', 'updatePassword',
    'updateProfile', 'vendorHome', 'vendorSearchTender', 'vendorViewTender', 'viewProfile'];
  for (const [role, pages] of [['admin', admin], ['user', vendor]]) {
    for (const page of pages) {
      const source = readFileSync(resolve(repo, `${page}.jsp`), 'utf8');
      assert.match(source, new RegExp(`!"${role}"\\.equalsIgnoreCase\\(user\\)`), page);
      assert.match(source, /uname\s*==\s*null/, page);
      assert.doesNotMatch(source, /session\.getAttribute\("password"\)|\bpword\b/, page);
      assert.match(source, /response\.sendRedirect\("loginFailed\.jsp"\);\s*return;/, page);
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
