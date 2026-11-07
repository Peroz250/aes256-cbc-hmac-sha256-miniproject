# AES-256-CBC with HMAC-SHA256

This project implements AES-256 encryption/decryption in Cipher Block Chaining (CBC) mode with HMAC-SHA256 authentication.

## Files

- `src/main/java/Aes256Crypto.java` - shared AES-256-CBC and HMAC-SHA256 engine.
- `src/main/java/AES256MainGUI.java` - Swing GUI version.
- `src/main/java/AES256CBC_HMAC.java` - console version.
- `scripts/run.bat` - compiles the project and launches the GUI.
- `scripts/run_console.bat` - compiles the project and launches the console version.
- `docs/Performance_Report.md` - performance tables, evaluation, and conclusion.
- `samples/` - example input and encrypted/decrypted sample files.
- `build/classes/` - generated compiled files after running a script.

## Requirements

- Java 8 or newer.

## Compile GUI Version

```powershell
scripts\run.bat
```

## Run GUI Version

```powershell
java -cp build\classes AES256MainGUI
```

The GUI includes:

1. A Text tab for manual text encryption/decryption.
2. A File tab for file encryption/decryption.
3. Visible HMAC-SHA256 fields.
4. A Compare HMAC button.
5. A Performance Analysis tab for Table 1 and Table 2.

Important: decryption requires the HMAC value. The program verifies the entered HMAC before decrypting.

## Run Console Version

```powershell
scripts\run_console.bat
```

The menu allows the user to:

1. Enter plaintext manually and encrypt it.
2. Paste encrypted Base64 text, enter the HMAC, and decrypt it.
3. Enter a file path and encrypt the file.
4. Enter an encrypted file path, enter the HMAC, and decrypt the file.
5. Run the performance analysis tables.

## Run Performance Analysis Only

```powershell
javac --release 8 -d build\classes src\main\java\*.java
java -cp build\classes AES256CBC_HMAC --benchmark
```

## Security Design

- AES mode: `AES/CBC/PKCS5Padding`
- AES key size: 256 bits
- AES-256 rounds: 14, handled by the Java Cryptography Architecture provider
- IV: random 16-byte IV for every encryption
- Salt: random 16-byte salt for every encryption
- Key derivation: PBKDF2-HMAC-SHA256
- Authentication: HMAC-SHA256
- Construction: encrypt-then-MAC, so the program verifies the HMAC before decryption
- GUI and console decryption require the user to provide the HMAC value, matching the sample project's HMAC workflow

## License

This project is licensed under the MIT License - see [LICENSE](LICENSE).
