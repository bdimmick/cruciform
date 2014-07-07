### cruciform: A Scala DSL for cryptographic operations

---

#### Examples and Comparisons

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


#### Operations


