import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.spec.KeySpec;
import java.util.Arrays;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

public final class Aes256Crypto {
    private static final byte[] MAGIC = "A256CBC1".getBytes(StandardCharsets.US_ASCII);
    private static final byte VERSION = 1;
    private static final int AES_KEY_BYTES = 32;
    private static final int HMAC_KEY_BYTES = 32;
    private static final int SALT_BYTES = 16;
    private static final int IV_BYTES = 16;
    private static final int HMAC_BYTES = 32;
    private static final int PBKDF2_ITERATIONS = 150000;
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    private Aes256Crypto() {
    }

    public static CryptoResult encrypt(byte[] plaintext, char[] password)
            throws GeneralSecurityException, IOException {
        long start = System.nanoTime();
        byte[] salt = randomBytes(SALT_BYTES);
        byte[] iv = randomBytes(IV_BYTES);
        KeyMaterial keys = deriveKeys(password, salt);

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, keys.aesKey, new IvParameterSpec(iv));
        byte[] ciphertext = cipher.doFinal(plaintext);

        byte[] authenticatedData = authenticatedData(salt, iv, ciphertext);
        byte[] hmac = hmacSha256(keys.hmacKey, authenticatedData);
        byte[] payload = buildPayload(salt, iv, ciphertext, hmac);

        long elapsed = System.nanoTime() - start;
        return CryptoResult.encrypted(payload, hmacToHex(hmac), plaintext.length, elapsed);
    }

    public static CryptoResult decrypt(byte[] payload, char[] password)
            throws GeneralSecurityException {
        return decryptParsedPayload(payload, password, null);
    }

    public static CryptoResult decrypt(byte[] payload, char[] password, String requiredHmacHex)
            throws GeneralSecurityException {
        if (requiredHmacHex == null || requiredHmacHex.trim().isEmpty()) {
            throw new GeneralSecurityException("Please insert HMAC.");
        }
        return decryptParsedPayload(payload, password, requiredHmacHex);
    }

    public static void verifyPayloadHmac(byte[] payload, char[] password, String requiredHmacHex)
            throws GeneralSecurityException {
        if (requiredHmacHex == null || requiredHmacHex.trim().isEmpty()) {
            throw new GeneralSecurityException("Please insert HMAC.");
        }
        verifyPayload(payload, password, requiredHmacHex);
    }

    private static CryptoResult decryptParsedPayload(byte[] payload, char[] password, String requiredHmacHex)
            throws GeneralSecurityException {
        long start = System.nanoTime();
        VerifiedPayload verified = verifyPayload(payload, password, requiredHmacHex);
        ParsedPayload parsed = verified.payload;

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, verified.keys.aesKey, new IvParameterSpec(parsed.iv));
        byte[] plaintext;
        try {
            plaintext = cipher.doFinal(parsed.ciphertext);
        } catch (BadPaddingException ex) {
            throw new GeneralSecurityException("Decryption failed after HMAC authentication.", ex);
        }

        long elapsed = System.nanoTime() - start;
        return CryptoResult.decrypted(plaintext, elapsed);
    }

    private static VerifiedPayload verifyPayload(byte[] payload, char[] password, String requiredHmacHex)
            throws GeneralSecurityException {
        ParsedPayload parsed = parsePayload(payload);
        KeyMaterial keys = deriveKeys(password, parsed.salt);
        byte[] authenticatedData = authenticatedData(parsed.salt, parsed.iv, parsed.ciphertext);
        byte[] expectedHmac = hmacSha256(keys.hmacKey, authenticatedData);

        if (!MessageDigest.isEqual(expectedHmac, parsed.hmac)) {
            throw new GeneralSecurityException("HMAC authentication failed. Password or data may be incorrect.");
        }
        if (requiredHmacHex != null) {
            byte[] userHmac = hexToBytes(requiredHmacHex.trim());
            if (!MessageDigest.isEqual(expectedHmac, userHmac)) {
                throw new GeneralSecurityException("HMAC authentication failed. Password, HMAC, or data may be incorrect.");
            }
        }
        return new VerifiedPayload(parsed, keys);
    }

    private static KeyMaterial deriveKeys(char[] password, byte[] salt) throws GeneralSecurityException {
        PBEKeySpec spec = new PBEKeySpec(password, salt, PBKDF2_ITERATIONS,
                (AES_KEY_BYTES + HMAC_KEY_BYTES) * 8);
        try {
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            byte[] derived = factory.generateSecret(spec).getEncoded();
            try {
                byte[] aesKeyBytes = Arrays.copyOfRange(derived, 0, AES_KEY_BYTES);
                byte[] hmacKeyBytes = Arrays.copyOfRange(derived, AES_KEY_BYTES, AES_KEY_BYTES + HMAC_KEY_BYTES);
                try {
                    return new KeyMaterial(
                            new SecretKeySpec(aesKeyBytes, "AES"),
                            new SecretKeySpec(hmacKeyBytes, "HmacSHA256"));
                } finally {
                    Arrays.fill(aesKeyBytes, (byte) 0);
                    Arrays.fill(hmacKeyBytes, (byte) 0);
                }
            } finally {
                Arrays.fill(derived, (byte) 0);
            }
        } finally {
            spec.clearPassword();
        }
    }

    private static byte[] randomBytes(int length) {
        byte[] bytes = new byte[length];
        SECURE_RANDOM.nextBytes(bytes);
        return bytes;
    }

    private static byte[] authenticatedData(byte[] salt, byte[] iv, byte[] ciphertext) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try {
            out.write(MAGIC);
            out.write(VERSION);
            out.write(salt);
            out.write(iv);
            out.write(ciphertext);
        } catch (IOException ex) {
            throw new IllegalStateException("Unexpected memory write failure", ex);
        }
        return out.toByteArray();
    }

    private static byte[] hmacSha256(SecretKeySpec hmacKey, byte[] data) throws GeneralSecurityException {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(hmacKey);
        return mac.doFinal(data);
    }

    private static byte[] buildPayload(byte[] salt, byte[] iv, byte[] ciphertext, byte[] hmac)
            throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(MAGIC);
        out.write(VERSION);
        out.write(salt);
        out.write(iv);
        out.write(ciphertext);
        out.write(hmac);
        return out.toByteArray();
    }

    private static ParsedPayload parsePayload(byte[] payload) throws GeneralSecurityException {
        int minimumLength = MAGIC.length + 1 + SALT_BYTES + IV_BYTES + HMAC_BYTES + 1;
        if (payload.length < minimumLength) {
            throw new GeneralSecurityException("Encrypted payload is too short.");
        }

        byte[] magic = Arrays.copyOfRange(payload, 0, MAGIC.length);
        if (!Arrays.equals(MAGIC, magic)) {
            throw new GeneralSecurityException("Unsupported encrypted payload format.");
        }

        byte version = payload[MAGIC.length];
        if (version != VERSION) {
            throw new GeneralSecurityException("Unsupported payload version: " + version);
        }

        int saltStart = MAGIC.length + 1;
        int ivStart = saltStart + SALT_BYTES;
        int ciphertextStart = ivStart + IV_BYTES;
        int hmacStart = payload.length - HMAC_BYTES;
        if (hmacStart <= ciphertextStart) {
            throw new GeneralSecurityException("Encrypted payload has no ciphertext.");
        }

        byte[] salt = Arrays.copyOfRange(payload, saltStart, ivStart);
        byte[] iv = Arrays.copyOfRange(payload, ivStart, ciphertextStart);
        byte[] ciphertext = Arrays.copyOfRange(payload, ciphertextStart, hmacStart);
        byte[] hmac = Arrays.copyOfRange(payload, hmacStart, payload.length);
        return new ParsedPayload(salt, iv, ciphertext, hmac);
    }

    private static String hmacToHex(byte[] hmac) {
        StringBuilder builder = new StringBuilder(hmac.length * 2);
        for (byte b : hmac) {
            builder.append(String.format("%02X", b));
        }
        return builder.toString();
    }

    private static byte[] hexToBytes(String hex) throws GeneralSecurityException {
        String normalized = hex.replaceAll("\\s+", "");
        if (normalized.length() != HMAC_BYTES * 2) {
            throw new GeneralSecurityException("Invalid HMAC hex value.");
        }

        byte[] bytes = new byte[normalized.length() / 2];
        for (int i = 0; i < normalized.length(); i += 2) {
            try {
                bytes[i / 2] = (byte) Integer.parseInt(normalized.substring(i, i + 2), 16);
            } catch (NumberFormatException ex) {
                throw new GeneralSecurityException("Invalid HMAC hex value.", ex);
            }
        }
        return bytes;
    }

    private static final class KeyMaterial {
        private final SecretKeySpec aesKey;
        private final SecretKeySpec hmacKey;

        private KeyMaterial(SecretKeySpec aesKey, SecretKeySpec hmacKey) {
            this.aesKey = aesKey;
            this.hmacKey = hmacKey;
        }
    }

    private static final class ParsedPayload {
        private final byte[] salt;
        private final byte[] iv;
        private final byte[] ciphertext;
        private final byte[] hmac;

        private ParsedPayload(byte[] salt, byte[] iv, byte[] ciphertext, byte[] hmac) {
            this.salt = salt;
            this.iv = iv;
            this.ciphertext = ciphertext;
            this.hmac = hmac;
        }
    }

    private static final class VerifiedPayload {
        private final ParsedPayload payload;
        private final KeyMaterial keys;

        private VerifiedPayload(ParsedPayload payload, KeyMaterial keys) {
            this.payload = payload;
            this.keys = keys;
        }
    }

    public static final class CryptoResult {
        public final byte[] payload;
        public final byte[] plaintext;
        public final String hmacHex;
        public final int bytesProcessed;
        public final long elapsedNanos;

        private CryptoResult(byte[] payload, byte[] plaintext, String hmacHex, int bytesProcessed, long elapsedNanos) {
            this.payload = payload;
            this.plaintext = plaintext;
            this.hmacHex = hmacHex;
            this.bytesProcessed = bytesProcessed;
            this.elapsedNanos = elapsedNanos;
        }

        private static CryptoResult encrypted(byte[] payload, String hmacHex, int bytesProcessed, long elapsedNanos) {
            return new CryptoResult(payload, null, hmacHex, bytesProcessed, elapsedNanos);
        }

        private static CryptoResult decrypted(byte[] plaintext, long elapsedNanos) {
            return new CryptoResult(null, plaintext, null, plaintext.length, elapsedNanos);
        }
    }
}
