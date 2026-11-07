package com.hit.security;

/** HTML text and quoted-attribute encoder for JSP interpolation. */
public final class HtmlEscaper {
    private HtmlEscaper() { }

    public static String escape(String input) {
        if (input == null) return "";
        StringBuilder result = new StringBuilder(input.length());
        for (int index = 0; index < input.length(); index++) {
            char character = input.charAt(index);
            switch (character) {
                case '&': result.append("&amp;"); break;
                case '<': result.append("&lt;"); break;
                case '>': result.append("&gt;"); break;
                case '"': result.append("&quot;"); break;
                case '\'': result.append("&#39;"); break;
                default: result.append(character);
            }
        }
        return result.toString();
    }
}
