package com.hexagrammatic.cruciform

import Ciphers._
import StreamUtils._

import java.io.ByteArrayOutputStream

import java.security.Key
import java.security.NoSuchAlgorithmException

import org.scalatest.FlatSpec
import org.scalatest.Matchers
import org.scalamock.scalatest.MockFactory


class CiphersSpec extends FlatSpec with Matchers with MockFactory {

  "Ciphers" should "be able to perform AES encryption with defaults" in {
    val key = Generators.key()
    val data = "Hello World"
    val ciphertext = new ByteArrayOutputStream()
    val plaintext = new ByteArrayOutputStream()
    val ivStream = new ByteArrayOutputStream()
    
    val ivHandler = (iv: Array[Byte]) => {
      ivStream.write(iv)
    } 
    
    encrypt(data, key, copyHandler(ciphertext), ivHandler)
    decrypt(ciphertext.toByteArray, key, copyHandler(plaintext), Option(ivStream.toByteArray))
    
    data.getBytes should not equal (ciphertext.toByteArray)
    data.getBytes should equal (plaintext.toByteArray)
  }

  "Ciphers" should "be able to perform AES encryption with ECB without init vector" in {
    val alg = Option("AES/ECB/PKCS5Padding")
    val key = Generators.key()
    val data = "Hello World"
    val ciphertext = new ByteArrayOutputStream()
    val plaintext = new ByteArrayOutputStream()
    
    encrypt(data, key, copyHandler(ciphertext), algorithm = alg)
    decrypt(ciphertext.toByteArray, key, copyHandler(plaintext), algorithm = alg)
    
    data.getBytes should not equal (ciphertext.toByteArray)
    data.getBytes should equal (plaintext.toByteArray)
  }

  "Ciphers" should "be able to perform DES encryption with defaults" in {
    val key = Generators.key("DES")
    val data = "Hello World"
    val ciphertext = new ByteArrayOutputStream()
    val plaintext = new ByteArrayOutputStream()
    val ivStream = new ByteArrayOutputStream()
    
    val ivHandler = (iv: Array[Byte]) => {
      ivStream.write(iv)
    } 
    
    encrypt(data, key, copyHandler(ciphertext), ivHandler)
    decrypt(ciphertext.toByteArray, key, copyHandler(plaintext), Option(ivStream.toByteArray))
    
    data.getBytes should not equal (ciphertext.toByteArray)
    data.getBytes should equal (plaintext.toByteArray)
  }

  "Ciphers" should "be able to perform RSA encryption" in {
    val keypair = Generators.keypair()
    val data = "Hello World"
    val ciphertext = new ByteArrayOutputStream()
    val plaintext = new ByteArrayOutputStream()
    
    encrypt(data, keypair, copyHandler(ciphertext))
    decrypt(ciphertext.toByteArray, keypair, copyHandler(plaintext))
    
    data.getBytes should not equal (ciphertext.toByteArray)
    data.getBytes should equal (plaintext.toByteArray)
  }

  "Ciphers" should "throw an exception with an illegal specified algorithm in encrypt" in {
    intercept[NoSuchAlgorithmException] {
      encrypt(
        "Hello World",
        Generators.key(),
        copyHandler(new ByteArrayOutputStream()),
        algorithm = Option("BAD"))
    }
  }

  "Ciphers" should "throw an exception with an illegal derived algorithm in encrypt" in {
    val key = mock[Key]

    (key.getAlgorithm _) expects() returning("BAD")

    intercept[NoSuchAlgorithmException] {
      encrypt("Hello World", key, copyHandler(new ByteArrayOutputStream()))
    }
  }

  "Ciphers" should "be able to sign and verify data with defaults" in {
    val keypair = Generators.keypair()
    val data = "Hello World"

    val signature = sign(data, keypair)

    // Valid verification with paired key
    verify(data, keypair, signature) should equal (true)

    // Invalid verificiation with different key
    verify(data, Generators.keypair(), signature) should equal (false)
  }

  "Ciphers" should "be able to sign and verify data with RSA and specifics" in {
    val keypair = Generators.keypair()
    val data = "Hello World"
    val algorithm = Option("SHA1withRSA")

    val signature = sign(data, keypair, algorithm = algorithm)

    // Valid verification with paired key and same algorithm
    verify(data, keypair, signature, algorithm = algorithm) should equal (true)

    // Invalid verificiation with paired key and different algorithm
    verify(data, keypair, signature) should equal (false)
  }

}