package com.hexagrammatic.cruciform

import Digests._
import StreamUtils.copyHandler

import java.io.ByteArrayOutputStream
import java.security.Key
import java.security.MessageDigest

import javax.crypto.Mac

import org.scalatest.FlatSpec
import org.scalatest.Matchers


class DigestsSpec extends FlatSpec with Matchers {

  def assertDigest(data: String, digest: Array[Byte], alg: String = DefaultDigestAlgorithm) {
    digest should not be (null)
    MessageDigest.getInstance(alg).digest(data.getBytes) should equal (digest)
  }

  def assertHMAC(data: String, key: Key, hmac: Array[Byte], alg: String = DefaultHMACAlgorithm) {
    hmac should not be null

    val mac = Mac.getInstance(alg)
    mac.init(key)
    
    mac.doFinal(data.getBytes) should equal (hmac)
  }

  "Digest" should "be able to digest data with default parameters" in {
    val data = "Hello World"
    assertDigest(data, digest(data = data))
  }

  "Digest" should "be able to digest data with specific algorithm" in {
    val alg = "SHA-1"
    val data = "Hello World"
    assertDigest(data, digest(data = data, algorithm = alg), alg = alg)
  }

  "Digest" should "be able to digest data with a stream handler" in {
    val data = "Hello World"

    val out = new ByteArrayOutputStream()

    assertDigest(data, digest(data = data, streamHandler = copyHandler(out)))
    data.getBytes should equal (out.toByteArray)
  }

  "HMAC" should "be able to digest data with default parameters" in {
    val k = Generators.key()
    val data = "Hello World"
    assertHMAC(data, k, hmac(data, k))
  }

  "HMAC" should "be able to digest data with specific algorithm" in {
    val k = Generators.key()
    val alg = "HmacSHA1"
    val data = "Hello World"
    assertHMAC(data, k, hmac(data, k, algorithm = alg), alg = alg)
  }

  "HMAC" should "be able to digest data with a stream handler" in {
    val k = Generators.key()
    val alg = "HmacSHA1"
    val data = "Hello Whirl"

    val out = new ByteArrayOutputStream()

    assertHMAC(data, k, hmac(data, k, algorithm = alg, streamHandler = copyHandler(out)), alg = alg)
    data.getBytes should equal (out.toByteArray)
  }

}