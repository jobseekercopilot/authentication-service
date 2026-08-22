package com.jobseekercopilot.authenticationservice.identity;

import java.net.IDN;
import java.text.Normalizer;
import java.util.Locale;
import org.springframework.stereotype.Component;

@Component
public class EmailIdentityCanonicalizer {

    public EmailIdentity normalize(String input) {
        if (input == null) {
            return new EmailIdentity("", "");
        }
        String display = Normalizer.normalize(stripUnicodeSpace(input), Normalizer.Form.NFC);
        String canonical = canonicalize(display);
        return new EmailIdentity(display, canonical);
    }

    private String canonicalize(String display) {
        String normalized = Normalizer.normalize(display, Normalizer.Form.NFKC);
        int separator = normalized.lastIndexOf('@');
        if (separator <= 0 || separator == normalized.length() - 1) {
            return normalized.toLowerCase(Locale.ROOT);
        }
        String localPart = normalized.substring(0, separator).toLowerCase(Locale.ROOT);
        String domain = normalized.substring(separator + 1);
        try {
            return localPart + "@" + IDN.toASCII(domain, IDN.USE_STD3_ASCII_RULES)
                    .toLowerCase(Locale.ROOT);
        } catch (IllegalArgumentException exception) {
            return normalized.toLowerCase(Locale.ROOT);
        }
    }

    private String stripUnicodeSpace(String value) {
        int start = 0;
        int end = value.length();
        while (start < end) {
            int codePoint = value.codePointAt(start);
            if (!isSpace(codePoint)) {
                break;
            }
            start += Character.charCount(codePoint);
        }
        while (start < end) {
            int codePoint = value.codePointBefore(end);
            if (!isSpace(codePoint)) {
                break;
            }
            end -= Character.charCount(codePoint);
        }
        return value.substring(start, end);
    }

    private boolean isSpace(int codePoint) {
        return Character.isWhitespace(codePoint) || Character.isSpaceChar(codePoint);
    }

    public record EmailIdentity(String display, String canonical) {
    }
}
