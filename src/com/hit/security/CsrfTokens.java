package com.hit.security;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;
import javax.servlet.http.HttpSession;

/** A per-session synchronizer token for sensitive form submissions. */
public final class CsrfTokens {
    private static final String ATTRIBUTE = CsrfTokens.class.getName() + ".value";
    private static final SecureRandom RANDOM = new SecureRandom();

    private CsrfTokens() { }

    public static String getOrCreate(HttpSession session) {
        if (session == null) throw new IllegalArgumentException("An authenticated session is required");
        synchronized (session) {
            Object existing = session.getAttribute(ATTRIBUTE);
            if (existing instanceof String && !((String) existing).isEmpty()) return (String) existing;
            byte[] randomBytes = new byte[32];
            RANDOM.nextBytes(randomBytes);
            String token = Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes);
            session.setAttribute(ATTRIBUTE, token);
            return token;
        }
    }

    public static boolean verify(HttpSession session, String submitted) {
        if (session == null || submitted == null || submitted.length() != 43) return false;
        Object expected = session.getAttribute(ATTRIBUTE);
        if (!(expected instanceof String)) return false;
        return MessageDigest.isEqual(
                ((String) expected).getBytes(StandardCharsets.US_ASCII),
                submitted.getBytes(StandardCharsets.US_ASCII));
    }
}
