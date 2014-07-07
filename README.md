### cruciform: A Scala DSL for cryptographic operations

---

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

##### Digest Operations

Trait: `com.hexagrammatic.cruciform.Digests`

###### Provides:
+ `encrypt data *data* using *key* [withAlgorithm(algorithm)] [withProvider(provider)]`


##### Cipher Operations

Trait: `com.hexagrammatic.cruciform.Ciphers`

###### Provides:

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
val sha = digest data target withAlgorithm("SHA-256") toBytes
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

