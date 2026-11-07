import java.io.BufferedReader;
import java.io.Console;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.Base64;
import java.util.Locale;
import java.util.Random;

public class AES256CBC_HMAC {
    private static final BufferedReader READER = new BufferedReader(new InputStreamReader(System.in));

    public static void main(String[] args) {
        if (args.length > 0 && "--benchmark".equalsIgnoreCase(args[0])) {
            runBenchmarks();
            return;
        }

        printHeader();
        while (true) {
            System.out.println();
            System.out.println("1. Encrypt text");
            System.out.println("2. Decrypt text");
            System.out.println("3. Encrypt file");
            System.out.println("4. Decrypt file");
            System.out.println("5. Run performance analysis");
            System.out.println("6. Exit");
            System.out.print("Choose an option: ");

            String choice;
            try {
                choice = READER.readLine().trim();
            } catch (IOException ex) {
                System.out.println("Error reading input.");
                continue;
            }

            try {
                if ("1".equals(choice)) {
                    encryptText();
                } else if ("2".equals(choice)) {
                    decryptText();
                } else if ("3".equals(choice)) {
                    encryptFile();
                } else if ("4".equals(choice)) {
                    decryptFile();
                } else if ("5".equals(choice)) {
                    runBenchmarks();
                } else if ("6".equals(choice)) {
                    System.out.println("Goodbye.");
                    return;
                } else {
                    System.out.println("Invalid option. Please select 1 to 6.");
                }
            } catch (Exception ex) {
                System.out.println("Operation failed: " + ex.getMessage());
            }
        }
    }

    private static void printHeader() {
        System.out.println("AES-256-CBC Encryption/Decryption with HMAC-SHA256");
        System.out.println("Mode: AES/CBC/PKCS5Padding | Key size: 256 bits | AES rounds: 14");
        System.out.println("Authentication: Encrypt-then-MAC using HMAC-SHA256");
    }

    private static void encryptText() throws GeneralSecurityException, IOException {
        System.out.print("Enter plaintext text: ");
        String plaintext = READER.readLine();
        char[] password = readPassword("Enter password: ");

        Aes256Crypto.CryptoResult result = Aes256Crypto.encrypt(
                plaintext.getBytes(StandardCharsets.UTF_8), password);
        Arrays.fill(password, '\0');

        System.out.println();
        System.out.println("Encrypted text payload:");
        System.out.println(Base64.getEncoder().encodeToString(result.payload));
        System.out.println("HMAC-SHA256:");
        System.out.println(result.hmacHex);
        printTiming(result);
    }

    private static void decryptText() throws GeneralSecurityException, IOException {
        System.out.print("Paste encrypted Base64 text payload: ");
        String base64Payload = READER.readLine().trim();
        char[] password = readPassword("Enter password: ");
        String hmacHex = promptHmac();

        Aes256Crypto.CryptoResult result;
        try {
            byte[] payload = Base64.getDecoder().decode(base64Payload);
            result = Aes256Crypto.decrypt(payload, password, hmacHex);
        } finally {
            Arrays.fill(password, '\0');
        }

        System.out.println();
        System.out.println("Decrypted text:");
        System.out.println(new String(result.plaintext, StandardCharsets.UTF_8));
        printTiming(result);
    }

    private static void encryptFile() throws GeneralSecurityException, IOException {
        Path input = promptPath("Enter input file path: ");
        if (!Files.isRegularFile(input)) {
            throw new IOException("Input file does not exist: " + input);
        }

        Path output = promptOutputPath("Enter encrypted output path, or press Enter for default: ",
                input.resolveSibling(input.getFileName().toString() + ".aes256"));
        char[] password = readPassword("Enter password: ");

        byte[] plaintext = Files.readAllBytes(input);
        Aes256Crypto.CryptoResult result = Aes256Crypto.encrypt(plaintext, password);
        Arrays.fill(password, '\0');
        Files.write(output, result.payload);

        System.out.println("Encrypted file written to: " + output.toAbsolutePath());
        System.out.println("HMAC-SHA256:");
        System.out.println(result.hmacHex);
        printTiming(result);
    }

    private static void decryptFile() throws GeneralSecurityException, IOException {
        Path input = promptPath("Enter encrypted input file path: ");
        if (!Files.isRegularFile(input)) {
            throw new IOException("Input file does not exist: " + input);
        }

        String name = input.getFileName().toString();
        Path defaultOutput = name.endsWith(".aes256")
                ? input.resolveSibling(name.substring(0, name.length() - ".aes256".length()) + ".decrypted")
                : input.resolveSibling(name + ".decrypted");
        Path output = promptOutputPath("Enter decrypted output path, or press Enter for default: ", defaultOutput);
        char[] password = readPassword("Enter password: ");
        String hmacHex = promptHmac();

        Aes256Crypto.CryptoResult result;
        try {
            byte[] payload = Files.readAllBytes(input);
            result = Aes256Crypto.decrypt(payload, password, hmacHex);
        } finally {
            Arrays.fill(password, '\0');
        }
        Files.write(output, result.plaintext);

        System.out.println("Decrypted file written to: " + output.toAbsolutePath());
        printTiming(result);
    }

    private static String promptHmac() throws IOException {
        System.out.print("Enter HMAC-SHA256: ");
        return READER.readLine().trim();
    }

    private static Path promptPath(String prompt) throws IOException {
        System.out.print(prompt);
        return Paths.get(stripQuotes(READER.readLine().trim()));
    }

    private static Path promptOutputPath(String prompt, Path defaultPath) throws IOException {
        System.out.print(prompt);
        String entered = stripQuotes(READER.readLine().trim());
        return entered.isEmpty() ? defaultPath : Paths.get(entered);
    }

    private static String stripQuotes(String value) {
        if (value.length() >= 2 && value.startsWith("\"") && value.endsWith("\"")) {
            return value.substring(1, value.length() - 1);
        }
        return value;
    }

    private static char[] readPassword(String prompt) {
        Console console = System.console();
        if (console != null) {
            return console.readPassword(prompt);
        }

        System.out.print(prompt);
        try {
            String line = READER.readLine();
            return line != null ? line.toCharArray() : new char[0];
        } catch (IOException ex) {
            System.err.println("Error reading password: " + ex.getMessage());
            return new char[0];
        }
    }

    private static void printTiming(Aes256Crypto.CryptoResult result) {
        double milliseconds = result.elapsedNanos / 1_000_000.0;
        double mb = result.bytesProcessed / (1024.0 * 1024.0);
        double seconds = result.elapsedNanos / 1_000_000_000.0;
        double throughput = seconds == 0.0 ? 0.0 : mb / seconds;
        System.out.printf(Locale.US, "Time: %.3f ms | Data: %d bytes | Throughput: %.3f MB/s%n",
                milliseconds, result.bytesProcessed, throughput);
    }

    private static void runBenchmarks() {
        System.out.println();
        System.out.println("Performance Analysis");
        System.out.println("Password-based key derivation is included in each encryption/decryption timing.");
        System.out.println("Each result is the average of 3 runs.");

        char[] password = "benchmark-password".toCharArray();

        System.out.println();
        System.out.println("Table 1: File size variation");
        System.out.println("| File sample | Size | Encrypt avg (ms) | Decrypt avg (ms) | Encrypt MB/s | Decrypt MB/s |");
        System.out.println("|---|---:|---:|---:|---:|---:|");
        benchmarkFiles(password);

        System.out.println();
        System.out.println("Table 2: Text size variation");
        System.out.println("| Text sample | Characters | Encrypt avg (ms) | Decrypt avg (ms) | Encrypt MB/s | Decrypt MB/s |");
        System.out.println("|---|---:|---:|---:|---:|---:|");
        benchmarkTexts(password);
        Arrays.fill(password, '\0');
    }

    private static void benchmarkFiles(char[] password) {
        int[] sizes = {1024, 10 * 1024, 100 * 1024, 1024 * 1024, 5 * 1024 * 1024};
        String[] labels = {
                "Tiny text file",
                "Small document",
                "Medium image-like file",
                "Large audio-like file",
                "Very large video-like file"
        };
        for (int i = 0; i < sizes.length; i++) {
            BenchmarkResult result = benchmark(deterministicBytes(sizes[i]), password);
            printFileBenchmarkRow(labels[i], sizes[i], result);
        }
    }

    private static void benchmarkTexts(char[] password) {
        int[] sizes = {128, 1024, 10 * 1024, 100 * 1024, 1024 * 1024};
        for (int size : sizes) {
            byte[] data = deterministicText(size).getBytes(StandardCharsets.UTF_8);
            BenchmarkResult result = benchmark(data, password);
            System.out.printf(Locale.US, "| Text %,d chars | %,d | %.3f | %.3f | %.3f | %.3f |%n",
                    size, size, result.encryptMs, result.decryptMs, result.encryptMbps, result.decryptMbps);
        }
    }

    private static BenchmarkResult benchmark(byte[] data, char[] password) {
        int runs = 3;
        long encryptTotal = 0;
        long decryptTotal = 0;

        try {
            for (int i = 0; i < runs; i++) {
                Aes256Crypto.CryptoResult encrypted = Aes256Crypto.encrypt(data, password);
                Aes256Crypto.CryptoResult decrypted = Aes256Crypto.decrypt(encrypted.payload, password);
                if (!Arrays.equals(data, decrypted.plaintext)) {
                    throw new IllegalStateException("Benchmark verification failed.");
                }
                encryptTotal += encrypted.elapsedNanos;
                decryptTotal += decrypted.elapsedNanos;
            }
        } catch (GeneralSecurityException | IOException ex) {
            throw new IllegalStateException("Benchmark failed: " + ex.getMessage(), ex);
        }

        double encryptMs = (encryptTotal / (double) runs) / 1_000_000.0;
        double decryptMs = (decryptTotal / (double) runs) / 1_000_000.0;
        double mb = data.length / (1024.0 * 1024.0);
        double encryptSeconds = (encryptTotal / (double) runs) / 1_000_000_000.0;
        double decryptSeconds = (decryptTotal / (double) runs) / 1_000_000_000.0;
        return new BenchmarkResult(encryptMs, decryptMs, mb / encryptSeconds, mb / decryptSeconds);
    }

    private static void printFileBenchmarkRow(String label, int bytes, BenchmarkResult result) {
        System.out.printf(Locale.US, "| %s | %,d bytes | %.3f | %.3f | %.3f | %.3f |%n",
                label, bytes, result.encryptMs, result.decryptMs, result.encryptMbps, result.decryptMbps);
    }

    private static byte[] deterministicBytes(int length) {
        byte[] data = new byte[length];
        new Random(256).nextBytes(data);
        return data;
    }

    private static String deterministicText(int characters) {
        String seed = "AES-256 CBC mode encrypts blocks with a random IV and HMAC verifies integrity. ";
        StringBuilder builder = new StringBuilder(characters);
        while (builder.length() < characters) {
            builder.append(seed);
        }
        return builder.substring(0, characters);
    }

    private static final class BenchmarkResult {
        final double encryptMs;
        final double decryptMs;
        final double encryptMbps;
        final double decryptMbps;

        BenchmarkResult(double encryptMs, double decryptMs, double encryptMbps, double decryptMbps) {
            this.encryptMs = encryptMs;
            this.decryptMs = decryptMs;
            this.encryptMbps = encryptMbps;
            this.decryptMbps = decryptMbps;
        }
    }
}
