package com.hexagrammatic.cruciform

import org.scalatest.FlatSpec
import org.scalatest.Matchers


class GeneratorsSpec extends FlatSpec with Matchers with KeyGenerators {

  "AES generator" should "be able to generate a key with defaults" in {
    ((AES key).getAlgorithm) should equal ("AES")
  }

  "DES generator" should "be able to generate a key with defaults" in {
    ((DES key).getAlgorithm) should equal ("DES")
  }

  "Blowfish generator" should "be able to generate a key with defaults" in {
    ((Blowfish key).getAlgorithm) should equal ("Blowfish")
  }

  "In general, key generators" should "be able to generate a key with a strength" in {
    val str = 128
    val k = AES strength(str bit) key

    ((AES key).getAlgorithm) should equal ("AES")
    k.getEncoded.length should equal (str / 8)
  }

  "RSA generator" should "be able to generate a keypair with no params" in {
    val pair = RSA keypair
    
    pair should not be null
    pair.getPrivate should not be null
    pair.getPublic should not be null
  }

  "DSA generator" should "be able to generate a keypair with no params" in {
    val pair = DSA keypair

    pair should not be null
    pair.getPrivate should not be null
    pair.getPublic should not be null
  }

  "In general, keypair generators" should "be able to generate a keypair with strength" in {
    val str = 1024
    val pair = RSA strength(str bit) keypair

    pair should not be null
    pair.getPrivate should not be null
    pair.getPublic should not be null
  }
}