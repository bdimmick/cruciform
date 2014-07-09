### cruciform: A Scala DSL for cryptographic operations

---

#### Setup

1. Install [JCE Unlimited Strength Policy](http://www.oracle.com/technetwork/java/javase/downloads/jce-7-download-432124.html)
2. `git clone https://github.com/bdimmick/cruciform.git`
3. `cd cruciform; sbt test package`

#### Usage

Cruciform provides functionality through traits that are mixed into the classes and objects that need to perform cryptographic operations.

##### Key Generation

Trait: `com.hexagrammatic.cruciform.KeyGenerators`

###### Provides:

Symmetric Key Generation
+ `AES [strength(bits)] [withProvider(provider)] key`
+ `Blowfish [strength(bits)] [withProvider(provider)] key`
+ `DES [strength(bits)] [withProvider(provider)] key`

Asymmetric Keypair Generation
+ `DSA [strength(bits)] [withProvider(provider)] keypair`
+ `RSA [strength(bits)] [withProvider(provider)] keypair`

###### Example

```Scala
import com.hexagrammatic.cruciform.KeyGenerators

object Example extends KeyGenerators {
  val key = AES key
  val keypair = RSA strength(1024 bit) keypair
}

```

##### Cipher Operations

Trait: `com.hexagrammatic.cruciform.Ciphers`

###### Provides:
+ `encrypt data <data> using <key> [withAlgorithm(algorithm)] [withProvider(provider)]
  to <stream>`
+ `decrypt data <data> using <key> [withAlgorithm(algorithm)] [withProvider(provider)]
  [withInitVector(iv)] to <stream>`
+ `sign data <data> using <key> [withAlgorithm(algorithm)] [withProvider(provider)] to <stream>`
+ `verify signature <data> using <key> [withAlgorithm(algorithm)] [withProvider(provider)]
  from <data>`

Notes: 
+ In the `encrypt`, `decrypt`, and `sign` operations, `data <data>` and the `key <key>` may be
  switched if desired.  Same for `signature <data>` and `using <key>` in `verify`.
+ Instead of `to <stream>`, `asBytes` or `asString` may be used to return raw bytes or a string in
   the above operations.
+ The `<data>` value may be one of the following:
  + `InputStream`
  + `Serializable`
  + `String`
  + `Array[Bytes]`
  + `Array[Char]`
  + `File`
  + `Readable`
+ The `<stream>` value may be one of the following:
  + `OutputStream`
  + `File`
+ Encrypt behaves slightly differently based on the key type provided.
  + When a `SecretKey` (symmetric key) is provided to `encrypt`, the return type is a`(OutputStream, 
    Option[Array[Byte]])` tuple consisting of the stream to which the ciphertext is written and an
    optional init vector, if one was created for the operation.  Similarly, `asBytes` and 
    `asString`, which returns a `(Array[Byte], Option[Array[Byte]])` or a `(String, 
    Option[Array[Byte]])` respectively.
  + When a `PublicKey`, `KeyPair`, or `Certificate` is provided to `encrypt`, the return type is
    a `OutputStream`, with `asBytes` returning an `Array[Byte]` and `asString` returning a 
    `String`.
+ If `withAlgorithm` is omitted, the language will pick the most appropriate one for the key type:
  + AES uses `AES/CBC/PKCS5Padding`
  + DES uses `DES/CBC/PKCS5Padding`
  + RSA uses `RSA/ECB/PKCS1Padding`
  + Other key types must provide the algorithm

###### Example

```Scala
import com.hexagrammatic.cruciform.Ciphers

object example extends Ciphers with KeyGenerators {
  val plaintext = "Hello world"

  // Symmetric encryption and decryption
  val key = AES key
  val (encrypted, iv) = encrypt data plaintext using key asBytes
  val decrypted = decrypt data encrypted using key withInitVector iv asBytes

  // Asymmetric encryption and decryption
  val keypair = RSA keypair
  val encrypted = encrypt data plaintext using keypair asBytes
  val decrypted = decrypt data encrypted using keypair iv asBytes

  // Asymmetric sign and verify
  val sig = sign data plaintext using keypair asBytes
  val verified = verify signature sig using keypair from plaintext
}
```

##### Digest Operations

Trait: `com.hexagrammatic.cruciform.Digests`

###### Provides:
+ `digest data <data> [withAlgorithm(algorithm)] [withProvider(provider)] to <stream>`
+ `hmac data <data> using <key> [withAlgorithm(algorithm)] [withProvider(provider)] to <stream>`

Notes:
+ In the `hmac` operation, `data <data>` and the `key <key>` may be switched if desired. 
+ If `withAlgorithm` is omitted, SHA-256 will be used for both digest and hmac.
+ The `<data>` value may be one of the following:
  + `InputStream`
  + `Serializable`
  + `String`
  + `Array[Bytes]`
  + `Array[Char]`
  + `File`
  + `Readable`
+ The `<stream>` value may be one of the following:
  + `OutputStream`
  + `File`
+ Instead of `to <stream>`, `asBytes` or `asString` may be used to return `Array[Byte]` or `String`
  respectively in the above operations.

```Scala

import com.hexagrammatic.cruciform.Digests

object Example extends Digests with KeyGenerators {
  val str = "Hello World"

  val digestSHA = digest data str asBytes

  val key = AES key
  val hmacSHA = hmac data str using key asBytes
}

```

---

#### Comparison with JCE

##### SHA256 Digest of a File:

###### JCE:
```Scala
val target = new File("target")
val digestor = MessageDigest.getInstance("SHA-256")
val buffer = new Array[Byte](128 * 1024)
val in = new DigestInputStream(new FileInputStream(target), digestor)

while (-1 != in.read(buffer)) {}

val digest = digestor.digest
```

###### Cruciform:
```Scala
val target = new File("target")
val sha = digest data target withAlgorithm("SHA-256") asBytes
```

*Symmetric Key Generation:*

###### JCE:
```Scala
val generator = KeyGenerator.getInstance("AES")
generator.init(128)
val key = generator.generateKey
```

###### Cruciform:
```Scala
val key = AES strength(128 bit) key
```

##### Symmetric Encryption of a File:

###### JCE:
```Scala
val in = new File("plaintext")
val out = new File("ciphertext")

val cipher = Cipher.getInstance("AES")
cipher.init(key, Cipher.ENCRYPT)

org.apache.commons.io.IOUtils.copy(in, new CipherOutputStream(out, cipher))

in.close()
out.close()
```

###### Cruciform:
```Scala
val in = new File("plaintext")
val out = new File("ciphertext")

encrypt data in using key to out

in close
out close
```

