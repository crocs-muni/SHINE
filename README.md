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
