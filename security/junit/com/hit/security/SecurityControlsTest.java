package com.hit.security;

import java.lang.reflect.Proxy;
import java.util.HashMap;
import java.util.Map;
import javax.servlet.FilterChain;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import org.junit.Test;
import static org.junit.Assert.*;

/** Unit tests use synthetic request/session proxies; no live application or database. */
public class SecurityControlsTest {
    private static HttpSession session(Map<String, Object> attributes) {
        return (HttpSession) Proxy.newProxyInstance(HttpSession.class.getClassLoader(),
                new Class<?>[]{HttpSession.class}, (proxy, method, args) -> {
                    if ("getAttribute".equals(method.getName())) return attributes.get(args[0]);
                    if ("setAttribute".equals(method.getName())) {
                        attributes.put((String) args[0], args[1]);
                        return null;
                    }
                    throw new UnsupportedOperationException(method.getName());
                });
    }

    private static HttpServletRequest request(String method, HttpSession session, String token) {
        return (HttpServletRequest) Proxy.newProxyInstance(HttpServletRequest.class.getClassLoader(),
                new Class<?>[]{HttpServletRequest.class}, (proxy, called, args) -> {
                    if ("getMethod".equals(called.getName())) return method;
                    if ("getSession".equals(called.getName())) return session;
                    if ("getParameter".equals(called.getName())) return "csrfToken".equals(args[0]) ? token : null;
                    throw new UnsupportedOperationException(called.getName());
                });
    }

    private static final class Result {
        int status;
        int forwarded;
        final Map<String, String> headers = new HashMap<>();

        HttpServletResponse response() {
            return (HttpServletResponse) Proxy.newProxyInstance(HttpServletResponse.class.getClassLoader(),
                    new Class<?>[]{HttpServletResponse.class}, (proxy, called, args) -> {
                        if ("setHeader".equals(called.getName())) {
                            headers.put((String) args[0], (String) args[1]);
                            return null;
                        }
                        if ("sendError".equals(called.getName())) {
                            status = (Integer) args[0];
                            return null;
                        }
                        throw new UnsupportedOperationException(called.getName());
                    });
        }
    }

    private static Result evaluate(String method, HttpSession session, String token) throws Exception {
        Result result = new Result();
        FilterChain chain = (request, response) -> result.forwarded++;
        new MutatingActionFilter().doFilter(request(method, session, token), result.response(), chain);
        return result;
    }

    @Test
    public void synchronizerTokenIsStableWithinSessionAndCannotBeGuessedFromOtherSession() {
        HttpSession first = session(new HashMap<>());
        HttpSession second = session(new HashMap<>());
        String token = CsrfTokens.getOrCreate(first);
        assertEquals(43, token.length());
        assertEquals(token, CsrfTokens.getOrCreate(first));
        assertNotEquals(token, CsrfTokens.getOrCreate(second));
        assertTrue(CsrfTokens.verify(first, token));
        assertFalse(CsrfTokens.verify(first, null));
        assertFalse(CsrfTokens.verify(first, token.substring(1)));
        String altered = token.substring(0, 42) + (token.charAt(42) == 'A' ? 'B' : 'A');
        assertFalse(CsrfTokens.verify(first, altered));
        assertFalse(CsrfTokens.verify(second, token));
    }

    @Test
    public void htmlEscaperHandlesNullMarkupQuotedAttributesAndUnicode() {
        assertEquals("", HtmlEscaper.escape(null));
        assertEquals("", HtmlEscaper.escape(""));
        assertEquals("Text &amp; &lt;tag&gt; &quot;quoted&quot; &#39;single&#39;",
                HtmlEscaper.escape("Text & <tag> \"quoted\" 'single'"));
        assertEquals("नमस्ते", HtmlEscaper.escape("नमस्ते"));
    }

    @Test
    public void filterRejectsGetMissingTokenAndVendorRole() throws Exception {
        Map<String, Object> attributes = new HashMap<>();
        attributes.put("user", "admin");
        attributes.put("username", "manager");
        HttpSession admin = session(attributes);
        String token = CsrfTokens.getOrCreate(admin);

        Result get = evaluate("GET", admin, token);
        assertEquals(405, get.status);
        assertEquals("POST", get.headers.get("Allow"));
        assertEquals(0, get.forwarded);

        Result missingToken = evaluate("POST", admin, null);
        assertEquals(403, missingToken.status);
        assertEquals(0, missingToken.forwarded);

        Result noSession = evaluate("POST", null, token);
        assertEquals(403, noSession.status);

        attributes.put("user", "user");
        Result vendor = evaluate("POST", admin, token);
        assertEquals(403, vendor.status);
        assertEquals(0, vendor.forwarded);

        attributes.put("user", 42);
        Result invalidRoleType = evaluate("POST", admin, token);
        assertEquals(403, invalidRoleType.status);
        assertEquals(0, invalidRoleType.forwarded);
    }

    @Test
    public void filterAllowsAuthorizedAdminPostWithMatchingToken() throws Exception {
        Map<String, Object> attributes = new HashMap<>();
        attributes.put("user", "admin");
        attributes.put("username", "manager");
        HttpSession admin = session(attributes);
        String token = CsrfTokens.getOrCreate(admin);
        Result valid = evaluate("POST", admin, token);
        assertEquals(0, valid.status);
        assertEquals(1, valid.forwarded);
        assertEquals("no-store", valid.headers.get("Cache-Control"));

        attributes.put("username", " ");
        Result blankIdentity = evaluate("POST", admin, token);
        assertEquals(403, blankIdentity.status);
        assertEquals(0, blankIdentity.forwarded);
    }
}
