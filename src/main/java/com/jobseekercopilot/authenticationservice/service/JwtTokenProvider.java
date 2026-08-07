package com.jobseekercopilot.authenticationservice.service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.security.SignatureException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.Clock;
import java.time.Duration;
import java.util.Base64;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Component
public class JwtTokenProvider {

    static final int MINIMUM_RSA_KEY_BITS = 2048;
    static final long MAXIMUM_ACCESS_TOKEN_LIFETIME_MS = 3_600_000;
    private static final String ALGORITHM = "RS256";
    private static final String ACCESS_TOKEN_TYPE = "access";
    private static final String ACCOUNT_LIFECYCLE_TOKEN_TYPE = "account_lifecycle";
    private static final String SESSION_ID_CLAIM = "sid";
    private static final String TOKEN_TYPE_CLAIM = "token_type";

    private final PrivateKey privateKey;
    private final Map<String, PublicKey> verificationKeys;
    private final List<Map<String, String>> jsonWebKeys;
    private final long expirationMs;
    private final String issuer;
    private final String audience;
    private final String keyId;
    private final long clockSkewSeconds;
    private final Duration accountLifecycleTokenLifetime;
    private final Clock clock;

    @Autowired
    public JwtTokenProvider(
            @Value("${jwt.private-key-base64}") String privateKeyBase64,
            @Value("${jwt.public-key-base64}") String publicKeyBase64,
            @Value("${jwt.previous-public-keys:}") String previousPublicKeys,
            @Value("${jwt.expiration:900000}") long expirationMs,
            @Value("${jwt.issuer:job-seeker-copilot-authentication}") String issuer,
            @Value("${jwt.audience:job-seeker-copilot-services}") String audience,
            @Value("${jwt.key-id:primary}") String keyId,
            @Value("${jwt.clock-skew-seconds:30}") long clockSkewSeconds,
            @Value("${auth.account-lifecycle.token-lifetime:5m}")
            Duration accountLifecycleTokenLifetime,
            Clock clock) {
        this(parsePrivateKey(privateKeyBase64), parsePublicKey(publicKeyBase64),
                parsePreviousKeys(previousPublicKeys), expirationMs, issuer, audience, keyId,
                clockSkewSeconds, accountLifecycleTokenLifetime, clock);
    }

    public JwtTokenProvider(
            String privateKeyBase64,
            String publicKeyBase64,
            String previousPublicKeys,
            long expirationMs,
            String issuer,
            String audience,
            String keyId,
            long clockSkewSeconds,
            Clock clock) {
        this(privateKeyBase64, publicKeyBase64, previousPublicKeys, expirationMs,
                issuer, audience, keyId, clockSkewSeconds, Duration.ofMinutes(5), clock);
    }

    JwtTokenProvider(
            PrivateKey privateKey, PublicKey publicKey, Map<String, PublicKey> previousPublicKeys,
            long expirationMs, String issuer, String audience, String keyId,
            long clockSkewSeconds, Clock clock) {
        this(privateKey, publicKey, previousPublicKeys, expirationMs, issuer, audience,
                keyId, clockSkewSeconds, Duration.ofMinutes(5), clock);
    }

    JwtTokenProvider(
            PrivateKey privateKey, PublicKey publicKey, Map<String, PublicKey> previousPublicKeys,
            long expirationMs, String issuer, String audience, String keyId,
            long clockSkewSeconds, Duration accountLifecycleTokenLifetime, Clock clock) {
        validateConfiguration(privateKey, publicKey, previousPublicKeys, expirationMs,
                issuer, audience, keyId, clockSkewSeconds);
        this.privateKey = privateKey;
        this.expirationMs = expirationMs;
        this.issuer = issuer;
        this.audience = audience;
        this.keyId = keyId;
        this.clockSkewSeconds = clockSkewSeconds;
        if (accountLifecycleTokenLifetime == null
                || accountLifecycleTokenLifetime.isZero()
                || accountLifecycleTokenLifetime.isNegative()
                || accountLifecycleTokenLifetime.compareTo(Duration.ofMinutes(15)) > 0) {
            throw new IllegalStateException(
                    "Account-lifecycle token lifetime must be between 1ms and 15 minutes");
        }
        this.accountLifecycleTokenLifetime = accountLifecycleTokenLifetime;
        this.clock = clock;

        Map<String, PublicKey> keys = new LinkedHashMap<>();
        keys.put(keyId, publicKey);
        keys.putAll(previousPublicKeys);
        this.verificationKeys = Map.copyOf(keys);
        this.jsonWebKeys = keys.entrySet().stream()
                .map(entry -> toJsonWebKey(entry.getKey(), (RSAPublicKey) entry.getValue()))
                .toList();
    }

    public String generateAccessToken(String userId, String sessionId) {
        Date now = Date.from(clock.instant());
        return Jwts.builder()
                .header().keyId(keyId).and()
                .issuer(issuer)
                .audience().add(audience).and()
                .subject(userId)
                .id(UUID.randomUUID().toString())
                .claim(SESSION_ID_CLAIM, sessionId)
                .claim(TOKEN_TYPE_CLAIM, ACCESS_TOKEN_TYPE)
                .issuedAt(now)
                .expiration(new Date(now.getTime() + expirationMs))
                .signWith(privateKey, Jwts.SIG.RS256)
                .compact();
    }

    public String generateAccountLifecycleToken(String userId, String operationId) {
        Date now = Date.from(clock.instant());
        return Jwts.builder()
                .header().keyId(keyId).and()
                .issuer(issuer)
                .audience().add(audience).and()
                .subject(userId)
                .id(UUID.randomUUID().toString())
                .claim("operation_id", operationId)
                .claim(TOKEN_TYPE_CLAIM, ACCOUNT_LIFECYCLE_TOKEN_TYPE)
                .issuedAt(now)
                .expiration(Date.from(clock.instant().plus(accountLifecycleTokenLifetime)))
                .signWith(privateKey, Jwts.SIG.RS256)
                .compact();
    }

    public AccessTokenClaims parseAccessToken(String token) {
        Jws<Claims> parsed = Jwts.parser()
                .keyLocator(header -> locateVerificationKey(header.getAlgorithm(), header.get("kid")))
                .requireIssuer(issuer)
                .requireAudience(audience)
                .clockSkewSeconds(clockSkewSeconds)
                .clock(() -> Date.from(clock.instant()))
                .build()
                .parseSignedClaims(token);
        Claims claims = parsed.getPayload();
        if (!ALGORITHM.equals(parsed.getHeader().getAlgorithm())
                || !ACCESS_TOKEN_TYPE.equals(claims.get(TOKEN_TYPE_CLAIM, String.class))
                || claims.getId() == null || claims.getId().isBlank()) {
            throw new JwtException("Access token metadata is invalid");
        }
        String userId = claims.getSubject();
        String sessionId = claims.get(SESSION_ID_CLAIM, String.class);
        if (userId == null || userId.isBlank() || sessionId == null || sessionId.isBlank()) {
            throw new JwtException("Access token claims are invalid");
        }
        return new AccessTokenClaims(userId, sessionId);
    }

    public List<Map<String, String>> getJsonWebKeys() {
        return jsonWebKeys;
    }

    public long getExpirationSeconds() {
        return expirationMs / 1000;
    }

    public String generateToken(String userId) {
        return generateAccessToken(userId, "legacy-test-session");
    }

    public String getUserIdFromToken(String token) {
        return parseAccessToken(token).userId();
    }

    private Key locateVerificationKey(String algorithm, Object rawKeyId) {
        if (!ALGORITHM.equals(algorithm)) {
            throw new UnsupportedJwtException("Only RS256 access tokens are supported");
        }
        if (!(rawKeyId instanceof String tokenKeyId) || tokenKeyId.isBlank()) {
            throw new SignatureException("Access token key ID is missing");
        }
        PublicKey key = verificationKeys.get(tokenKeyId);
        if (key == null) {
            throw new SignatureException("Access token key ID is not recognised");
        }
        return key;
    }

    private static void validateConfiguration(
            PrivateKey privateKey, PublicKey publicKey, Map<String, PublicKey> previousPublicKeys,
            long expirationMs, String issuer, String audience, String keyId, long clockSkewSeconds) {
        if (!(privateKey instanceof RSAPrivateCrtKey rsaPrivate)
                || !(publicKey instanceof RSAPublicKey rsaPublic)) {
            throw configurationFailure();
        }
        if (rsaPublic.getModulus().bitLength() < MINIMUM_RSA_KEY_BITS
                || rsaPrivate.getModulus().bitLength() < MINIMUM_RSA_KEY_BITS
                || !rsaPrivate.getModulus().equals(rsaPublic.getModulus())
                || !rsaPrivate.getPublicExponent().equals(rsaPublic.getPublicExponent())) {
            throw configurationFailure();
        }
        for (PublicKey previous : previousPublicKeys.values()) {
            if (!(previous instanceof RSAPublicKey rsa) || rsa.getModulus().bitLength() < MINIMUM_RSA_KEY_BITS) {
                throw configurationFailure();
            }
        }
        if (expirationMs <= 0 || expirationMs > MAXIMUM_ACCESS_TOKEN_LIFETIME_MS) {
            throw new IllegalStateException("JWT access-token lifetime must be between 1ms and 1 hour");
        }
        if (issuer == null || issuer.isBlank() || audience == null || audience.isBlank()
                || keyId == null || keyId.isBlank() || previousPublicKeys.containsKey(keyId)) {
            throw new IllegalStateException("JWT issuer, audience and unique key IDs must be configured");
        }
        if (clockSkewSeconds < 0 || clockSkewSeconds > 300) {
            throw new IllegalStateException("JWT clock skew must be between 0 and 300 seconds");
        }
    }

    private static PrivateKey parsePrivateKey(String encoded) {
        try {
            return KeyFactory.getInstance("RSA").generatePrivate(
                    new PKCS8EncodedKeySpec(decodeRequired(encoded)));
        } catch (GeneralSecurityException | IllegalArgumentException exception) {
            throw configurationFailure();
        }
    }

    private static PublicKey parsePublicKey(String encoded) {
        try {
            return KeyFactory.getInstance("RSA").generatePublic(
                    new X509EncodedKeySpec(decodeRequired(encoded)));
        } catch (GeneralSecurityException | IllegalArgumentException exception) {
            throw configurationFailure();
        }
    }

    private static Map<String, PublicKey> parsePreviousKeys(String configured) {
        if (configured == null || configured.isBlank()) {
            return Map.of();
        }
        Map<String, PublicKey> keys = new LinkedHashMap<>();
        for (String entry : configured.split(",")) {
            int separator = entry.indexOf('=');
            if (separator <= 0 || separator == entry.length() - 1) {
                throw configurationFailure();
            }
            String id = entry.substring(0, separator).trim();
            if (id.isBlank() || keys.putIfAbsent(id, parsePublicKey(entry.substring(separator + 1).trim())) != null) {
                throw configurationFailure();
            }
        }
        return Map.copyOf(keys);
    }

    private static byte[] decodeRequired(String encoded) {
        if (encoded == null || encoded.isBlank()) {
            throw configurationFailure();
        }
        return Base64.getDecoder().decode(encoded.trim());
    }

    private static IllegalStateException configurationFailure() {
        return new IllegalStateException("JWT RSA key configuration is missing or invalid");
    }

    private static Map<String, String> toJsonWebKey(String id, RSAPublicKey key) {
        Map<String, String> jwk = new LinkedHashMap<>();
        jwk.put("kty", "RSA");
        jwk.put("use", "sig");
        jwk.put("alg", ALGORITHM);
        jwk.put("kid", id);
        jwk.put("n", base64UrlUnsigned(key.getModulus()));
        jwk.put("e", base64UrlUnsigned(key.getPublicExponent()));
        return Map.copyOf(jwk);
    }

    private static String base64UrlUnsigned(BigInteger value) {
        byte[] signed = value.toByteArray();
        int offset = signed.length > 1 && signed[0] == 0 ? 1 : 0;
        byte[] unsigned = new byte[signed.length - offset];
        System.arraycopy(signed, offset, unsigned, 0, unsigned.length);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(unsigned);
    }
}
