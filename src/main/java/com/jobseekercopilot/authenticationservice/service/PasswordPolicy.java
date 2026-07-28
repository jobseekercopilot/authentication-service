package com.jobseekercopilot.authenticationservice.service;

import com.jobseekercopilot.authenticationservice.exception.BadRequestException;
import com.jobseekercopilot.authenticationservice.identity.EmailIdentityCanonicalizer;
import com.jobseekercopilot.authenticationservice.model.RegisterRequest;
import com.jobseekercopilot.authenticationservice.model.User;
import org.springframework.stereotype.Component;

import java.text.Normalizer;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Pattern;

@Component
public class PasswordPolicy {

    static final int MINIMUM_CODE_POINTS = 15;
    static final int MAXIMUM_CODE_POINTS = 128;

    private static final int MAXIMUM_EMAIL_LENGTH = 254;
    private static final int MAXIMUM_NAME_LENGTH = 100;
    private static final Pattern EMAIL = Pattern.compile("^[^\\s@]+@[^\\s@]+\\.[^\\s@]+$");
    private static final Set<String> BLOCKED_PASSWORDS = Set.of(
            "passwordpassword",
            "password123456",
            "123456789012345",
            "qwertyuiopasdfgh",
            "letmeinletmein",
            "correct horse battery staple",
            "iloveyouiloveyou",
            "adminadminadmin",
            "welcome123456789",
            "changemechangeme"
    );
    private final EmailIdentityCanonicalizer emailCanonicalizer;

    public PasswordPolicy(EmailIdentityCanonicalizer emailCanonicalizer) {
        this.emailCanonicalizer = emailCanonicalizer;
    }

    public void validateRegistration(RegisterRequest request) {
        if (request == null || request.getEmail() == null || request.getPassword() == null
                || request.getName() == null) {
            throw new BadRequestException("Name, email and password are required.");
        }

        String name = request.getName().trim();
        var emailIdentity = emailCanonicalizer.normalize(request.getEmail());
        String email = emailIdentity.display();
        String password = request.getPassword();

        if (name.isEmpty() || name.codePointCount(0, name.length()) > MAXIMUM_NAME_LENGTH) {
            throw new BadRequestException("Name must contain between 1 and 100 characters.");
        }
        if (email.isEmpty() || email.length() > MAXIMUM_EMAIL_LENGTH
                || emailIdentity.canonical().length() > MAXIMUM_EMAIL_LENGTH
                || !EMAIL.matcher(email).matches()) {
            throw new BadRequestException("Enter a valid email address.");
        }

        validatePassword(password, name, emailIdentity.canonical());
    }

    public void validateNewPassword(User user, String password) {
        if (user == null || password == null) {
            throw new BadRequestException("A new password is required.");
        }
        validatePassword(password, user.getName().trim(), user.getCanonicalEmail());
    }

    private void validatePassword(String password, String name, String canonicalEmail) {
        int codePoints = password.codePointCount(0, password.length());
        if (codePoints < MINIMUM_CODE_POINTS || codePoints > MAXIMUM_CODE_POINTS) {
            throw new BadRequestException("Password must contain between 15 and 128 characters.");
        }
        String comparison = Normalizer.normalize(password, Normalizer.Form.NFKC)
                .toLowerCase(Locale.ROOT);
        String emailLocalPart = canonicalEmail.substring(0, canonicalEmail.indexOf('@'));
        if (BLOCKED_PASSWORDS.contains(comparison)
                || comparison.equals(name.toLowerCase(Locale.ROOT))
                || comparison.equals(canonicalEmail)
                || comparison.equals(emailLocalPart)) {
            throw new BadRequestException("Choose a password that is not commonly used or based on account details.");
        }
    }
}
