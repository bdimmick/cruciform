package com.hexagrammatic.cruciform

import java.security.Key
import java.security.PrivateKey

import org.scalatest.{Matchers, FlatSpec}

class CodecsSpec extends FlatSpec with Matchers with KeyGenerators with Codecs with Ciphers {

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

  "Encoders" should "be able to encode a private key as a a PEM with a password" in {
    val keypair = RSA keypair
    val password = "password"
    val str = "Hello World"
    val ciphertext = encrypt data str using keypair.getPublic asBytes

    val encoded = PEM encode keypair.getPrivate withPassword password asBytes

    (PEM decode encoded asPrivateKey) should be (None)

    val pk = (PEM decode encoded withPassword password asPrivateKey) getOrElse fail
    val plaintext = decrypt data ciphertext using pk asString

    compareKeys(keypair.getPrivate, pk)
    (plaintext) should be (str)
  }


  "Encoders" should " not be able to find a private key if no data is present" in {
    (PEM decode "" asPrivateKey) should be (None)
  }

  "Encoders" should " not be able to find a private key if no key is present" in {
    val keypair = RSA keypair
    val encoded = PEM encode keypair.getPublic asBytes

    (PEM decode encoded asPrivateKey) should be (None)
  }

  "Encoders" should "be able to encode a public key as a a PEM" in {
    val keypair = RSA keypair
    val str = "Hello World"
    val sig = sign data str using keypair.getPrivate asBytes

    val encoded = PEM encode keypair.getPublic asBytes
    val pk = (PEM decode encoded asPublicKey) getOrElse fail

    compareKeys(keypair.getPublic, pk)
    (verify signature sig using pk from str) should be (true)
  }

  "Encoders" should " not be able to find a public key if no data is present" in {
    (PEM decode "" asPublicKey) should be (None)
  }

}
