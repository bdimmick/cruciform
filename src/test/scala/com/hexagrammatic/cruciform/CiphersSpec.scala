package com.hexagrammatic.cruciform

import Ciphers._
import Generators._
import StreamUtils._

import java.io.ByteArrayOutputStream

import org.scalatest.FlatSpec
import org.scalatest.Matchers


class CiphersSpec extends FlatSpec with Matchers {

  "Chipers" should "be able to perform AES encryption with defaults" in {
    val key = Generators.key()
    val data = "Hello World"
    val ciphertext = new ByteArrayOutputStream()
    val plaintext = new ByteArrayOutputStream()
    val ivStream = new ByteArrayOutputStream()
    
    val ivHandler = (iv: Array[Byte]) => {
      ivStream.write(iv)
    } 
    
    encrypt(data, key, copyHandler(ciphertext), Option(ivHandler))
    decrypt(ciphertext.toByteArray, key, copyHandler(plaintext), Option(ivStream.toByteArray))
    
    data.getBytes should not equal (ciphertext.toByteArray)
    data.getBytes should equal (plaintext.toByteArray)
  }

  "Chipers" should "be able to perform AES encryption with ECB without init vector" in {
    val transform = Option("AES/ECB/PKCS5Padding")
    val key = Generators.key()
    val data = "Hello World"
    val ciphertext = new ByteArrayOutputStream()
    val plaintext = new ByteArrayOutputStream()
    
    encrypt(data, key, copyHandler(ciphertext), transformation = transform)
    decrypt(ciphertext.toByteArray, key, copyHandler(plaintext), transformation = transform)
    
    data.getBytes should not equal (ciphertext.toByteArray)
    data.getBytes should equal (plaintext.toByteArray)
  }

  "Chipers" should "be able to perform DES encryption with defaults" in {
    val key = Generators.key("DES")
    val data = "Hello World"
    val ciphertext = new ByteArrayOutputStream()
    val plaintext = new ByteArrayOutputStream()
    val ivStream = new ByteArrayOutputStream()
    
    val ivHandler = (iv: Array[Byte]) => {
      ivStream.write(iv)
    } 
    
    encrypt(data, key, copyHandler(ciphertext), Option(ivHandler))
    decrypt(ciphertext.toByteArray, key, copyHandler(plaintext), Option(ivStream.toByteArray))
    
    data.getBytes should not equal (ciphertext.toByteArray)
    data.getBytes should equal (plaintext.toByteArray)
  }

  "Chipers" should "be able to perform RSA encryption" in {    
    val keypair = Generators.keypair()
    val data = "Hello World"
    val ciphertext = new ByteArrayOutputStream()
    val plaintext = new ByteArrayOutputStream()
    
    encrypt(data, keypair, copyHandler(ciphertext))
    decrypt(ciphertext.toByteArray, keypair, copyHandler(plaintext))
    
    data.getBytes should not equal (ciphertext.toByteArray)
    data.getBytes should equal (plaintext.toByteArray)
  }

}