package com.hexagrammatic.cruciform

import java.security.Key
import java.security.PrivateKey

import org.scalatest.{Matchers, FlatSpec}

class EncodersSpec extends FlatSpec with Matchers with KeyGenerators with Encoders with Ciphers {

  def compareKeys(original: Key, possible: Key) {
    (possible.getAlgorithm) should be (original.getAlgorithm)
    (possible.getFormat) should be (original.getFormat)
    (possible.getEncoded) should be (original.getEncoded)
  }

  "Encoders" should "be able to encode a private key as a a PEM without password" in {
    val keypair = RSA keypair
    val str = "Hello World"
    val ciphertext = encrypt data str using keypair.getPublic asBytes

    val encoded = PEM encode keypair.getPrivate asBytes
    val pk = (PEM decode encoded asPrivateKey) getOrElse fail
    val plaintext = decrypt data ciphertext using pk asString

    compareKeys(keypair.getPrivate, pk)
    (plaintext) should be (str)
  }

}
