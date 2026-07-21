package com.jobseekercopilot.authenticationservice.identity;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

class EmailIdentityCanonicalizerTest {

    private final EmailIdentityCanonicalizer canonicalizer = new EmailIdentityCanonicalizer();

    @Test
    void stripsUnicodeEdgeSpaceAndPreservesDisplayCase() {
        var identity = canonicalizer.normalize("\u00a0Case.User@Example.Test\u2003");

        assertEquals("Case.User@Example.Test", identity.display());
        assertEquals("case.user@example.test", identity.canonical());
    }

    @Test
    void appliesCompatibilityNormalisationOnlyToCanonicalIdentity() {
        var identity = canonicalizer.normalize("Ｊöhn@ＥXAMPLE.test");

        assertEquals("Ｊöhn@ＥXAMPLE.test", identity.display());
        assertEquals("jöhn@example.test", identity.canonical());
    }

    @Test
    void composesEquivalentUnicodeDisplayForms() {
        var identity = canonicalizer.normalize("cafe\u0301@example.test");

        assertEquals("café@example.test", identity.display());
        assertEquals("café@example.test", identity.canonical());
    }

    @Test
    void unicodeAndAsciiDomainFormsShareOneIdentity() {
        var unicode = canonicalizer.normalize("user@bücher.example");
        var ascii = canonicalizer.normalize("USER@xn--bcher-kva.example");

        assertEquals("user@xn--bcher-kva.example", unicode.canonical());
        assertEquals(unicode.canonical(), ascii.canonical());
    }
}
