package com.jobseekercopilot.authenticationservice.service;

import com.jobseekercopilot.authenticationservice.exception.BadRequestException;
import com.jobseekercopilot.authenticationservice.model.RegisterRequest;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;

class PasswordPolicyTest {

    private final PasswordPolicy policy = new PasswordPolicy();

    @Test
    void acceptsLongUnicodePassphraseWithoutCompositionRules() {
        RegisterRequest request = new RegisterRequest("Zoë", "zoe@example.test", "🌱 a memorable café passphrase");

        assertDoesNotThrow(() -> policy.validateRegistration(request));
    }

    @Test
    void rejectsPasswordsShorterThanFifteenUnicodeCodePoints() {
        RegisterRequest request = new RegisterRequest("User", "user@example.test", "🌱short phrase");

        assertThrows(BadRequestException.class, () -> policy.validateRegistration(request));
    }

    @Test
    void rejectsPasswordsLongerThanOneHundredTwentyEightUnicodeCodePoints() {
        RegisterRequest request = new RegisterRequest("User", "user@example.test", "🌱".repeat(129));

        assertThrows(BadRequestException.class, () -> policy.validateRegistration(request));
    }

    @Test
    void rejectsKnownCompromisedPasswordCaseInsensitively() {
        RegisterRequest request = new RegisterRequest("User", "user@example.test", "CORRECT HORSE BATTERY STAPLE");

        assertThrows(BadRequestException.class, () -> policy.validateRegistration(request));
    }

    @Test
    void rejectsPasswordBasedOnAccountIdentity() {
        RegisterRequest request = new RegisterRequest("Long Account Name", "user@example.test", "long account name");

        assertThrows(BadRequestException.class, () -> policy.validateRegistration(request));
    }

    @Test
    void validatesNameAndEmailBounds() {
        assertThrows(BadRequestException.class,
                () -> policy.validateRegistration(new RegisterRequest("", "user@example.test", "A valid local passphrase")));
        assertThrows(BadRequestException.class,
                () -> policy.validateRegistration(new RegisterRequest("User", "not-an-email", "A valid local passphrase")));
    }
}
