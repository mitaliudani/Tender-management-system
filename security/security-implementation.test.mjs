import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync, mkdtempSync, rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join, resolve} from 'node:path';
import {spawnSync} from 'node:child_process';

const root = resolve(import.meta.dirname, '..');
const read = path => readFileSync(resolve(root, path), 'utf8');

test('bid decisions and notice removal use POST forms with synchronizer tokens', () => {
  const cases = [
    ['viewTenderBidsForm.jsp', 'AcceptBidSrv'],
    ['viewTenderBidsForm.jsp', 'RejectBidSrv'],
    ['removeNotice.jsp', 'RemoveNoticeSrv'],
  ];
  for (const [file, action] of cases) {
    const source = read(file);
    const escaped = action.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    const form = new RegExp(`<form\\s+action="${escaped}"\\s+method="post">([\\s\\S]*?)<\\/form>`, 'i').exec(source);
    assert.ok(form, `${file} must POST to ${action}`);
    assert.match(form[1], /name="csrfToken"\s+value="<%=CsrfTokens\.getOrCreate\(session\)%>"/);
    assert.doesNotMatch(source, new RegExp(`href="${escaped}\\?`));
  }
});

test('server-side filter rejects GET, missing admin role, and missing CSRF token', () => {
  const source = read('src/com/hit/security/MutatingActionFilter.java');
  for (const action of ['AcceptBidSrv', 'RejectBidSrv', 'RemoveNoticeSrv']) {
    assert.ok(source.includes(`"/${action}"`), `Missing filter mapping: ${action}`);
  }
  assert.match(source, /"POST"\.equals\(request\.getMethod\(\)\)/);
  assert.match(source, /"admin"\.equalsIgnoreCase\(\(String\) role\)/);
  assert.match(source, /CsrfTokens\.verify\(session, request\.getParameter\("csrfToken"\)\)/);
  assert.match(source, /chain\.doFilter\(rawRequest, rawResponse\)/);
});

test('HTML output encoder compiles and passes Java 8-compatible edge cases', () => {
  const directory = mkdtempSync(join(tmpdir(), 'tender-html-'));
  try {
    const compile = spawnSync('java', [
      'com.sun.tools.javac.Main', '-encoding', 'UTF-8', '-source', '8', '-target', '8', '-d', directory,
      resolve(root, 'src/com/hit/security/HtmlEscaper.java'),
      resolve(root, 'security/java-tests/HtmlEscaperTest.java'),
    ], {encoding: 'utf8'});
    assert.equal(compile.status, 0, compile.stderr || compile.stdout);
    const run = spawnSync('java', ['-cp', directory, 'HtmlEscaperTest'], {encoding: 'utf8'});
    assert.equal(run.status, 0, run.stderr || run.stdout);
  } finally {
    rmSync(directory, {recursive: true, force: true});
  }
});
