# SHINE

JavaCard implementation of SHINE - Smartcard Highly-Interoperable Nonce-Encryption scheme.

The code structure is based on [JavaCard Gradle template](https://github.com/ph4r05/javacard-gradle-template) and it uses [JCMathLib library](https://github.com/OpenCryptoProject/JCMathLib).

## Compilation

To build the applet, clone this repository with submodules and run:

```
./gradlew buildJavaCard
```

The resulting cap file can be found in `applet/build/javacard/shine.cap`

## Performance Measurement

Tests and performance measurementment can be performed by running:

```
./gradlew test
```

If you want to use a physical card, install the applet to the smartcard and change card type to `PHYSICAL` in `PerformaceTest.java` file, before running the command.

## APDU

| Name                    | CLA   | INS   | P1           | P2         | Data                                    |
| :---                    | :---: | :---: | :---:        | :---:      | :---                                    |
| `INFO`                  | 0x00  | 0xF0  | 0x00         | 0x00       | ---                                     |
| `IDENTITY`              | 0x00  | 0xF1  | 0x00         | 0x00       | ---                                     |
| `KEYGEN_INITIALIZE`     | 0x00  | 0x01  | `GROUP_SIZE` | 0x00       | ---                                     |
| `KEYGEN_ADD_COMMITMENT` | 0x00  | 0x02  | `IDX`        | 0x00       | 32B SHA256 of public key of `IDX` party |
| `KEYGEN_REVEAL`         | 0x00  | 0x03  | 0x00         | 0x00       | ---                                     |
| `KEYGEN_ADD_KEY`        | 0x00  | 0x04  | `IDX`        | 0x00       | 65B public key of `IDX` party           |
| `KEYGEN_FINALIZE`       | 0x00  | 0x05  | 0x00         | 0x00       | ---                                     |
| `GET_NONCE`             | 0x00  | 0x06  | `CTR_LOW`    | `CTR_HIGH` | ---                                     |
| `CACHE_NONCE`           | 0x00  | 0x07  | `CTR_LOW`    | `CTR_HIGH` | ---                                     |
| `REVEAL_NONCE`          | 0x00  | 0x08  | `CTR_LOW`    | `CTR_HIGH` | ---                                     |
| `SIGN`                  | 0x00  | 0x09  | `CTR_LOW`    | `CTR_HIGH` | 65B aggregate nonce + 32B message       |
| `SIGN_REVEAL`           | 0x00  | 0x0A  | `CTR_LOW`    | `CTR_HIGH` | 65B aggregate nonce + 32B message       |
| `SIGN_BIP`              | 0x00  | 0x0B  | `CTR_LOW`    | `CTR_HIGH` | 65B aggregate nonce + 32B message       |
| `SIGN_BIP_REVEAL`       | 0x00  | 0x0C  | `CTR_LOW`    | `CTR_HIGH` | 65B aggregate nonce + 32B message       |
