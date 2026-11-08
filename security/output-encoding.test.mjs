import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {resolve} from 'node:path';

const root = resolve(import.meta.dirname, '..');

// Text and double-quoted attribute positions in the selected JSP views.
// This does not validate JavaScript, CSS, URL encoding, or other JSP files.
const cases = [
  ['adminViewVendor.jsp', /\bvendor\.get(?:Id|Name|Mobile|Email|Company|Address)\(\)/],
  ['adminViewVendorDetail.jsp', /\bvendor\.get(?:Name|Mobile|Email|Company|Address)\(\)/],
  ['viewProfile.jsp', /\bvendor\.get(?:Id|Name|Mobile|Email|Company|Address)\(\)/],
  ['viewTender.jsp', /\b(?:tid|tname|ttype|tloc|tdesc)\b/],
  ['vendorViewTender.jsp', /\b(?:tname|ttype|tloc|tdesc)\b/],
  ['viewTenderBidsForm.jsp', /\b(?:bidder\.get\w+\(\)|status|request\.getParameter\(\"tid\"\))/],
];

test('six representative JSP views encode dynamic text and quoted-attribute fields', () => {
  let protectedExpressions = 0;
  for (const [path, riskyValue] of cases) {
    const content = readFileSync(resolve(root, path), 'utf8');
    assert.match(content, /<%@page import="com\.hit\.security\.HtmlEscaper"%>/,
      `${path} must import the HTML encoder`);
    for (const match of content.matchAll(/<%=\s*([\s\S]*?)\s*%>/g)) {
      const expression = match[1];
      if (riskyValue.test(expression)) {
        assert.match(expression, /^HtmlEscaper\.escape\(/,
          `${path} has an unencoded dynamic output: ${expression}`);
        protectedExpressions++;
      }
    }
  }
  assert.ok(protectedExpressions >= 25,
    `Expected at least 25 protected dynamic expressions; got ${protectedExpressions}`);
});
