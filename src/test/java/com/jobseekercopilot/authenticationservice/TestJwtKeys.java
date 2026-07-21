package com.jobseekercopilot.authenticationservice;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

public final class TestJwtKeys {

    public static final String ACTIVE_KEY_ID = "test-key";
    public static final KeyPair ACTIVE = generate();
    public static final KeyPair PREVIOUS = generate();
    public static final KeyPair DIFFERENT = generate();

    private TestJwtKeys() {
    }

    public static String privateKey(KeyPair pair) {
        return Base64.getEncoder().encodeToString(pair.getPrivate().getEncoded());
    }

    public static String publicKey(KeyPair pair) {
        return Base64.getEncoder().encodeToString(pair.getPublic().getEncoded());
    }

    private static KeyPair generate() {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048);
            return generator.generateKeyPair();
        } catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException("RSA is unavailable", exception);
        }
    }
}
