import com.hit.security.HtmlEscaper;

public final class HtmlEscaperTest {
    private static void assertEqual(String expected, String actual) {
        if (!expected.equals(actual)) throw new AssertionError("Expected: " + expected + "; received: " + actual);
    }

    public static void main(String[] args) {
        assertEqual("", HtmlEscaper.escape(null));
        assertEqual("", HtmlEscaper.escape(""));
        assertEqual("Text &amp; &lt;tag&gt; &quot;quoted&quot; &#39;single&#39;",
                HtmlEscaper.escape("Text & <tag> \"quoted\" 'single'"));
        assertEqual("नमस्ते", HtmlEscaper.escape("नमस्ते"));
    }
}
