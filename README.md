# Curve25519 Keyshare

Curve25519 is an elliptic curve offering 128 bits of security and designed for use with the elliptic curve Diffie–Hellman (ECDH) key agreement scheme. It is one of the fastest ECC curves

[![Version](https://img.shields.io/badge/Version-2.0-blue.svg)](https://github.com/NetRiceCake/Curve25519-keyshare/)

### Using in Gradle :
```
repositories {
  mavenCentral()
}

dependencies {
  implementation 'com.github.netricecake:x25519:2.0'
}
```

### Using in Maven :
```
<dependencies>
  <dependency>
    <groupId>com.github.netricecake</groupId>
    <artifactId>x25519</artifactId>
    <version>2.0</version>
  </dependency>
</dependencies>
```

### How to use :

Make private key :
```
Curve25519.generateRandomKey() //Return 32 byte random bytes
```

Make public key from private key :
```
Curve25519.publicKey(byte[] privateKey)
```

Get shared secret :
```
Curve25519.sharedSecrete(byte[] privateKey, byte[] publicKey) //Private key and Public key must be 32 byte array
```

Example :
```
byte[] aPrivate = Curve25519.generateRandomKey();
byte[] aPublic = Curve25519.publicKey(aPrivate);

byte[] bPrivate = Curve25519.generateRandomKey();
byte[] bPublic = Curve25519.publicKey(bPrivate);

byte[] aSharedSecret = Curve25519.sharedSecret(aPrivate, bPublic);
byte[] bSharedSecret = Curve25519.sharedSecret(bPrivate, aPublic);
```


### Additional
**Version 1.0 has one big problem.**
Please use version 2.0.