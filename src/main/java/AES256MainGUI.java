import java.awt.BorderLayout;
import java.awt.Desktop;
import java.awt.FlowLayout;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.Toolkit;
import java.awt.datatransfer.StringSelection;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.Base64;
import java.util.Locale;
import java.util.Random;
import javax.swing.JButton;
import javax.swing.JFileChooser;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTabbedPane;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.SwingUtilities;

public class AES256MainGUI extends JFrame {
    private final JTextArea textInputArea = new JTextArea(8, 42);
    private final JTextArea textOutputArea = new JTextArea(8, 42);
    private final JTextField textKeyField = new JTextField(32);
    private final JTextField textHmacField = new JTextField(48);
    private final JTextField textVerifyHmacField = new JTextField(48);
    private final JLabel textStatus = new JLabel("Please insert your text message and key.");

    private final JTextArea fileArea = new JTextArea(5, 42);
    private final JTextField fileKeyField = new JTextField(32);
    private final JTextField fileHmacField = new JTextField(48);
    private final JTextField fileVerifyHmacField = new JTextField(48);
    private final JLabel fileStatus = new JLabel("Click Browse File to insert a file.");
    private File selectedFile;
    private File lastOutputFile;

    private final JTextArea performanceArea = new JTextArea(22, 70);

    public static void main(String[] args) {
        SwingUtilities.invokeLater(new Runnable() {
            @Override
            public void run() {
                new AES256MainGUI().setVisible(true);
            }
        });
    }

    public AES256MainGUI() {
        super("AES-256 Security with HMAC");
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setSize(900, 680);
        setLocationRelativeTo(null);

        JTabbedPane tabs = new JTabbedPane();
        tabs.addTab("Text", buildTextPanel());
        tabs.addTab("File", buildFilePanel());
        tabs.addTab("Performance Analysis", buildPerformancePanel());
        add(tabs, BorderLayout.CENTER);
    }

    private JPanel buildTextPanel() {
        JPanel panel = new JPanel(new BorderLayout(8, 8));
        JPanel form = new JPanel(new GridBagLayout());
        GridBagConstraints c = constraints();

        addLabel(form, c, 0, "Input Text or Encrypted Text:");
        c.gridx = 1;
        c.gridy = 0;
        c.fill = GridBagConstraints.BOTH;
        c.weightx = 1;
        c.weighty = 0.3;
        textInputArea.setLineWrap(true);
        textInputArea.setWrapStyleWord(true);
        form.add(new JScrollPane(textInputArea), c);

        addLabel(form, c, 1, "Key / Password:");
        c.gridx = 1;
        c.gridy = 1;
        c.fill = GridBagConstraints.HORIZONTAL;
        c.weighty = 0;
        form.add(textKeyField, c);

        addLabel(form, c, 2, "Output:");
        c.gridx = 1;
        c.gridy = 2;
        c.fill = GridBagConstraints.BOTH;
        c.weighty = 0.3;
        textOutputArea.setLineWrap(true);
        textOutputArea.setWrapStyleWord(true);
        form.add(new JScrollPane(textOutputArea), c);

        addLabel(form, c, 3, "Generated HMAC-SHA256:");
        c.gridx = 1;
        c.gridy = 3;
        c.fill = GridBagConstraints.HORIZONTAL;
        c.weighty = 0;
        textHmacField.setEditable(false);
        form.add(textHmacField, c);

        addLabel(form, c, 4, "HMAC for Decryption:");
        c.gridx = 1;
        c.gridy = 4;
        form.add(textVerifyHmacField, c);

        JPanel buttons = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JButton encrypt = new JButton("Encrypt");
        JButton compare = new JButton("Compare HMAC");
        JButton decrypt = new JButton("Decrypt");
        JButton copyOutput = new JButton("Copy Output");
        JButton copyHmac = new JButton("Copy HMAC");
        JButton clear = new JButton("Clear");

        encrypt.addActionListener(e -> encryptText());
        compare.addActionListener(e -> compareTextHmac());
        decrypt.addActionListener(e -> decryptText());
        copyOutput.addActionListener(e -> copy(textOutputArea.getText(), "Output copied."));
        copyHmac.addActionListener(e -> copy(textHmacField.getText(), "HMAC copied."));
        clear.addActionListener(e -> clearText());

        buttons.add(encrypt);
        buttons.add(compare);
        buttons.add(decrypt);
        buttons.add(copyOutput);
        buttons.add(copyHmac);
        buttons.add(clear);

        panel.add(textStatus, BorderLayout.NORTH);
        panel.add(form, BorderLayout.CENTER);
        panel.add(buttons, BorderLayout.SOUTH);
        return panel;
    }

    private JPanel buildFilePanel() {
        JPanel panel = new JPanel(new BorderLayout(8, 8));
        JPanel form = new JPanel(new GridBagLayout());
        GridBagConstraints c = constraints();

        addLabel(form, c, 0, "File:");
        c.gridx = 1;
        c.gridy = 0;
        c.fill = GridBagConstraints.BOTH;
        c.weightx = 1;
        c.weighty = 0.2;
        fileArea.setEditable(false);
        fileArea.setLineWrap(true);
        fileArea.setWrapStyleWord(true);
        form.add(new JScrollPane(fileArea), c);

        addLabel(form, c, 1, "Key / Password:");
        c.gridx = 1;
        c.gridy = 1;
        c.fill = GridBagConstraints.HORIZONTAL;
        c.weighty = 0;
        form.add(fileKeyField, c);

        addLabel(form, c, 2, "Generated HMAC-SHA256:");
        c.gridx = 1;
        c.gridy = 2;
        fileHmacField.setEditable(false);
        form.add(fileHmacField, c);

        addLabel(form, c, 3, "HMAC for Decryption:");
        c.gridx = 1;
        c.gridy = 3;
        form.add(fileVerifyHmacField, c);

        JPanel buttons = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JButton browse = new JButton("Browse File");
        JButton encrypt = new JButton("Encrypt");
        JButton compare = new JButton("Compare HMAC");
        JButton decrypt = new JButton("Decrypt");
        JButton copyHmac = new JButton("Copy HMAC");
        JButton showFolder = new JButton("Show Folder");
        JButton clear = new JButton("Clear");

        browse.addActionListener(e -> browseFile());
        encrypt.addActionListener(e -> encryptFile());
        compare.addActionListener(e -> compareFileHmac());
        decrypt.addActionListener(e -> decryptFile());
        copyHmac.addActionListener(e -> copy(fileHmacField.getText(), "HMAC copied."));
        showFolder.addActionListener(e -> showOutputFolder());
        clear.addActionListener(e -> clearFile());

        buttons.add(browse);
        buttons.add(encrypt);
        buttons.add(compare);
        buttons.add(decrypt);
        buttons.add(copyHmac);
        buttons.add(showFolder);
        buttons.add(clear);

        panel.add(fileStatus, BorderLayout.NORTH);
        panel.add(form, BorderLayout.CENTER);
        panel.add(buttons, BorderLayout.SOUTH);
        return panel;
    }

    private JPanel buildPerformancePanel() {
        JPanel panel = new JPanel(new BorderLayout(8, 8));
        performanceArea.setEditable(false);
        performanceArea.setFont(new java.awt.Font("Monospaced", java.awt.Font.PLAIN, 12));

        JButton run = new JButton("Run Performance Analysis");
        run.addActionListener(e -> performanceArea.setText(runBenchmarks()));

        panel.add(new JLabel("AES-256-CBC with HMAC-SHA256 performance tables."), BorderLayout.NORTH);
        panel.add(new JScrollPane(performanceArea), BorderLayout.CENTER);
        panel.add(run, BorderLayout.SOUTH);
        return panel;
    }

    private GridBagConstraints constraints() {
        GridBagConstraints c = new GridBagConstraints();
        c.insets = new Insets(6, 6, 6, 6);
        c.anchor = GridBagConstraints.WEST;
        return c;
    }

    private void addLabel(JPanel panel, GridBagConstraints c, int row, String text) {
        c.gridx = 0;
        c.gridy = row;
        c.fill = GridBagConstraints.NONE;
        c.weightx = 0;
        c.weighty = 0;
        panel.add(new JLabel(text), c);
    }

    private void encryptText() {
        char[] password = textKeyField.getText().toCharArray();
        try {
            String message = textInputArea.getText();
            if (message.trim().isEmpty() || password.length == 0) {
                showError("Please define the key and message.");
                return;
            }

            Aes256Crypto.CryptoResult result = Aes256Crypto.encrypt(
                    message.getBytes(StandardCharsets.UTF_8), password);
            textOutputArea.setText(Base64.getEncoder().encodeToString(result.payload));
            textHmacField.setText(result.hmacHex);
            textVerifyHmacField.setText(result.hmacHex);
            textStatus.setText(String.format(Locale.US,
                    "Encryption successful. Time: %.3f ms. Copy the output and HMAC.",
                    result.elapsedNanos / 1_000_000.0));
            showMessage("Encryption Successful\nClick 'Copy Output' to copy the encrypted message.\nClick 'Copy HMAC' to copy HMAC.");
        } catch (Exception ex) {
            showError(ex.getMessage());
        } finally {
            Arrays.fill(password, '\0');
        }
    }

    private void compareTextHmac() {
        char[] password = textKeyField.getText().toCharArray();
        try {
            byte[] payload = Base64.getDecoder().decode(readEncryptedTextPayload());
            String enteredHmac = textVerifyHmacField.getText().trim();
            Aes256Crypto.verifyPayloadHmac(payload, password, enteredHmac);
            textStatus.setText("Message verified. HMAC is correct.");
            showMessage("Message Verified!\nClick 'Decrypt' to obtain the original text.");
        } catch (Exception ex) {
            showError("Message Verification Failed!\n" + ex.getMessage());
        } finally {
            Arrays.fill(password, '\0');
        }
    }

    private void decryptText() {
        char[] password = textKeyField.getText().toCharArray();
        try {
            byte[] payload = Base64.getDecoder().decode(readEncryptedTextPayload());
            String enteredHmac = textVerifyHmacField.getText().trim();
            Aes256Crypto.CryptoResult result = Aes256Crypto.decrypt(payload, password, enteredHmac);
            textOutputArea.setText(new String(result.plaintext, StandardCharsets.UTF_8));
            textStatus.setText(String.format(Locale.US,
                    "Decryption successful. HMAC verified first. Time: %.3f ms.",
                    result.elapsedNanos / 1_000_000.0));
            showMessage("Decryption Successful");
        } catch (Exception ex) {
            showError(ex.getMessage());
        } finally {
            Arrays.fill(password, '\0');
        }
    }

    private String readEncryptedTextPayload() {
        String input = textInputArea.getText().trim();
        return input.isEmpty() ? textOutputArea.getText().trim() : input;
    }

    private void clearText() {
        textInputArea.setText("");
        textOutputArea.setText("");
        textKeyField.setText("");
        textHmacField.setText("");
        textVerifyHmacField.setText("");
        textStatus.setText("Please insert your text message and key.");
    }

    private void browseFile() {
        JFileChooser chooser = new JFileChooser();
        int selected = chooser.showOpenDialog(this);
        if (selected == JFileChooser.APPROVE_OPTION) {
            selectedFile = chooser.getSelectedFile();
            fileArea.setText(selectedFile.getAbsolutePath());
            if (selectedFile.getName().endsWith(".aes256")) {
                fileStatus.setText("Encrypted file inserted. Insert key and HMAC, then compare or decrypt.");
            } else {
                fileStatus.setText("Normal file inserted. Define the key and click Encrypt.");
            }
        }
    }

    private void encryptFile() {
        char[] password = fileKeyField.getText().toCharArray();
        try {
            if (selectedFile == null || !selectedFile.isFile()) {
                showError("Please browse and select a file.");
                return;
            }
            if (password.length == 0) {
                showError("Please define the key.");
                return;
            }

            byte[] input = Files.readAllBytes(selectedFile.toPath());
            Aes256Crypto.CryptoResult result = Aes256Crypto.encrypt(input, password);
            lastOutputFile = new File(selectedFile.getParentFile(), selectedFile.getName() + ".aes256");
            Files.write(lastOutputFile.toPath(), result.payload);
            fileHmacField.setText(result.hmacHex);
            fileVerifyHmacField.setText(result.hmacHex);
            fileStatus.setText(String.format(Locale.US,
                    "Encryption successful. Output: %s. Time: %.3f ms.",
                    lastOutputFile.getName(), result.elapsedNanos / 1_000_000.0));
            showMessage("Encryption Successful\nYour encrypted file name is " + lastOutputFile.getName()
                    + "\nClick 'Copy HMAC' to copy HMAC.");
        } catch (Exception ex) {
            showError(ex.getMessage());
        } finally {
            Arrays.fill(password, '\0');
        }
    }

    private void compareFileHmac() {
        char[] password = fileKeyField.getText().toCharArray();
        try {
            if (selectedFile == null || !selectedFile.isFile()) {
                showError("Please browse and select an encrypted file.");
                return;
            }

            byte[] payload = Files.readAllBytes(selectedFile.toPath());
            String enteredHmac = fileVerifyHmacField.getText().trim();
            Aes256Crypto.verifyPayloadHmac(payload, password, enteredHmac);
            fileStatus.setText("File verified. HMAC is correct.");
            showMessage("File Verified!\nClick 'Decrypt' to obtain the original file.");
        } catch (Exception ex) {
            showError("File Verification Failed!\n" + ex.getMessage());
        } finally {
            Arrays.fill(password, '\0');
        }
    }

    private void decryptFile() {
        char[] password = fileKeyField.getText().toCharArray();
        try {
            if (selectedFile == null || !selectedFile.isFile()) {
                showError("Please browse and select an encrypted file.");
                return;
            }

            byte[] payload = Files.readAllBytes(selectedFile.toPath());
            String enteredHmac = fileVerifyHmacField.getText().trim();
            Aes256Crypto.CryptoResult result = Aes256Crypto.decrypt(payload, password, enteredHmac);

            String outputName = selectedFile.getName().endsWith(".aes256")
                    ? selectedFile.getName().substring(0, selectedFile.getName().length() - ".aes256".length()) + ".decrypted"
                    : selectedFile.getName() + ".decrypted";
            lastOutputFile = new File(selectedFile.getParentFile(), outputName);
            Files.write(lastOutputFile.toPath(), result.plaintext);
            fileStatus.setText(String.format(Locale.US,
                    "Decryption successful. Output: %s. Time: %.3f ms.",
                    lastOutputFile.getName(), result.elapsedNanos / 1_000_000.0));
            showMessage("Decryption Successful\nYour decrypted file name is " + lastOutputFile.getName());
        } catch (Exception ex) {
            showError(ex.getMessage());
        } finally {
            Arrays.fill(password, '\0');
        }
    }

    private void clearFile() {
        selectedFile = null;
        lastOutputFile = null;
        fileArea.setText("");
        fileKeyField.setText("");
        fileHmacField.setText("");
        fileVerifyHmacField.setText("");
        fileStatus.setText("Click Browse File to insert a file.");
    }

    private void showOutputFolder() {
        try {
            if (lastOutputFile == null) {
                showError("No output file has been created yet.");
                return;
            }
            if (!Desktop.isDesktopSupported()) {
                showError("Opening folders is not supported on this computer.");
                return;
            }
            Desktop.getDesktop().open(lastOutputFile.getParentFile());
        } catch (IOException ex) {
            showError(ex.getMessage());
        }
    }

    private void copy(String value, String message) {
        if (value == null || value.trim().isEmpty()) {
            showError("Nothing to copy.");
            return;
        }
        Toolkit.getDefaultToolkit().getSystemClipboard().setContents(new StringSelection(value), null);
        fileStatus.setText(message);
        textStatus.setText(message);
    }

    private void showMessage(String message) {
        JOptionPane.showMessageDialog(this, message, "Status", JOptionPane.INFORMATION_MESSAGE);
    }

    private void showError(String message) {
        JOptionPane.showMessageDialog(this, message, "Error", JOptionPane.ERROR_MESSAGE);
    }

    private String runBenchmarks() {
        StringBuilder out = new StringBuilder();
        out.append("Performance Analysis\n");
        out.append("Password-based key derivation and HMAC authentication are included in each timing.\n");
        out.append("Each result is the average of 3 runs.\n\n");

        char[] password = "benchmark-password".toCharArray();
        try {
            out.append("Table 1: File size variation\n");
            out.append(String.format("%-28s %12s %16s %16s %14s %14s%n",
                    "File sample", "Size", "Encrypt ms", "Decrypt ms", "Enc MB/s", "Dec MB/s"));
            int[] fileSizes = {1024, 10 * 1024, 100 * 1024, 1024 * 1024, 5 * 1024 * 1024};
            String[] labels = {
                    "Tiny text file",
                    "Small document",
                    "Medium image-like file",
                    "Large audio-like file",
                    "Very large video-like file"
            };
            for (int i = 0; i < fileSizes.length; i++) {
                BenchmarkResult result = benchmark(deterministicBytes(fileSizes[i]), password);
                out.append(String.format(Locale.US, "%-28s %,12d %16.3f %16.3f %14.3f %14.3f%n",
                        labels[i], fileSizes[i], result.encryptMs, result.decryptMs,
                        result.encryptMbps, result.decryptMbps));
            }

            out.append("\nTable 2: Text size variation\n");
            out.append(String.format("%-28s %12s %16s %16s %14s %14s%n",
                    "Text sample", "Characters", "Encrypt ms", "Decrypt ms", "Enc MB/s", "Dec MB/s"));
            int[] textSizes = {128, 1024, 10 * 1024, 100 * 1024, 1024 * 1024};
            for (int size : textSizes) {
                BenchmarkResult result = benchmark(deterministicText(size).getBytes(StandardCharsets.UTF_8), password);
                out.append(String.format(Locale.US, "%-28s %,12d %16.3f %16.3f %14.3f %14.3f%n",
                        "Text " + size + " chars", size, result.encryptMs, result.decryptMs,
                        result.encryptMbps, result.decryptMbps));
            }
        } finally {
            Arrays.fill(password, '\0');
        }
        return out.toString();
    }

    private BenchmarkResult benchmark(byte[] data, char[] password) {
        int runs = 3;
        long encryptTotal = 0;
        long decryptTotal = 0;

        try {
            for (int i = 0; i < runs; i++) {
                Aes256Crypto.CryptoResult encrypted = Aes256Crypto.encrypt(data, password);
                Aes256Crypto.CryptoResult decrypted = Aes256Crypto.decrypt(
                        encrypted.payload, password, encrypted.hmacHex);
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

    private byte[] deterministicBytes(int length) {
        byte[] data = new byte[length];
        new Random(256).nextBytes(data);
        return data;
    }

    private String deterministicText(int characters) {
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
