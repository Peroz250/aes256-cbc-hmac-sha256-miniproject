# Performance Analysis of AES-256 in CBC Mode with HMAC Authentication

## Objective

The project implements AES-256 encryption/decryption in Cipher Block Chaining (CBC) mode and adds HMAC-SHA256 authentication. The system accepts either manually entered text or a file path from the user. A Swing GUI version is provided with separate tabs for text, files, and performance analysis.

## Implementation Summary

- Programming language: Java
- Encryption algorithm: AES-256
- Mode of operation: CBC
- Padding: PKCS5Padding
- AES-256 rounds: 14
- Authentication: HMAC-SHA256
- Key derivation: PBKDF2-HMAC-SHA256 using a random salt
- IV handling: a new random 16-byte IV is generated for each encryption
- Integrity check: HMAC is verified before decryption
- HMAC workflow: encryption displays a HMAC value, and decryption requires the user to enter that HMAC before plaintext is released

The encrypted payload stores the format marker, version, salt, IV, ciphertext, and HMAC tag. For text encryption the payload is Base64 encoded so it can be copied and pasted. For file encryption the payload is written as binary data. The HMAC is also shown separately so the user can copy it, compare it, and provide it during decryption.

## Table 1: File Size Variation

These results were produced on the local machine by running:

```powershell
javac --release 8 -d build\classes src\main\java\*.java
java -cp build\classes AES256CBC_HMAC --benchmark
```

Each value is the average of 3 runs. Password-based key derivation is included in each encryption and decryption timing.

| File sample | Size | Encrypt avg (ms) | Decrypt avg (ms) | Encrypt MB/s | Decrypt MB/s |
|---|---:|---:|---:|---:|---:|
| Tiny text file | 1,024 bytes | 453.542 | 326.367 | 0.002 | 0.003 |
| Small document | 10,240 bytes | 312.008 | 324.004 | 0.031 | 0.030 |
| Medium image-like file | 102,400 bytes | 326.094 | 311.685 | 0.299 | 0.313 |
| Large audio-like file | 1,048,576 bytes | 325.153 | 319.065 | 3.075 | 3.134 |
| Very large video-like file | 5,242,880 bytes | 350.138 | 345.024 | 14.280 | 14.492 |

## Table 2: Text Size Variation

| Text sample | Characters | Encrypt avg (ms) | Decrypt avg (ms) | Encrypt MB/s | Decrypt MB/s |
|---|---:|---:|---:|---:|---:|
| Text 128 chars | 128 | 307.596 | 304.988 | 0.000 | 0.000 |
| Text 1,024 chars | 1,024 | 303.526 | 306.140 | 0.003 | 0.003 |
| Text 10,240 chars | 10,240 | 312.855 | 315.026 | 0.031 | 0.031 |
| Text 102,400 chars | 102,400 | 301.721 | 304.109 | 0.324 | 0.321 |
| Text 1,048,576 chars | 1,048,576 | 310.009 | 315.059 | 3.226 | 3.174 |

## Critical Evaluation

The results show that small files and short text have low throughput because the fixed setup cost is high compared with the amount of data being encrypted. In this implementation, each operation includes PBKDF2 key derivation, random salt/IV processing, AES setup, and HMAC calculation. For tiny inputs, those fixed costs dominate the total time.

As the file or text size increases, throughput improves significantly. For example, the 5 MB file sample reaches much higher MB/s than the 1 KB sample because the fixed setup cost is spread across more data. This shows that AES-256-CBC is more efficient for larger continuous inputs than for many very small independent messages.

Encryption and decryption times are close to each other. This is expected because AES-CBC encryption and decryption both process the same number of blocks, and HMAC-SHA256 also scans the authenticated data. Minor differences come from runtime scheduling, memory allocation, padding, and measurement variation.

The HMAC step adds important security value. CBC mode alone does not provide integrity or tamper detection. With HMAC-SHA256, modified ciphertext, an incorrect password, corrupted payload data, or an incorrect entered HMAC is detected before decryption is attempted.

## Conclusion

The upgraded AES system successfully uses a 256-bit key, AES-CBC encryption/decryption, and HMAC-SHA256 authentication. Performance improves as input size grows because fixed setup costs become less significant. For real systems, AES-256-CBC should always be combined with authentication, as done here, or replaced by an authenticated encryption mode such as AES-GCM.
