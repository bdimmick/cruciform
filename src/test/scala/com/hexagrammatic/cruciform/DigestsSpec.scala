package com.hexagrammatic.cruciform

import Digests._
import StreamUtils.copyHandler

import java.io.ByteArrayOutputStream
import java.security.Key
import java.security.MessageDigest

import javax.crypto.Mac

import org.scalatest.FlatSpec
import org.scalatest.Matchers


class DigestsSpec extends FlatSpec with Matchers with Digests {

  val str = "Hello World"

  def assertDigest(digest: Array[Byte], alg: String = DefaultDigestAlgorithm) {
    digest should not be (null)
    MessageDigest.getInstance(alg).digest(str.getBytes) should equal (digest)
  }

  def assertHMAC(key: Key, hmac: Array[Byte], alg: String = DefaultHMACAlgorithm) {
    hmac should not be null

    val mac = Mac.getInstance(alg)
    mac.init(key)
    
    mac.doFinal(str.getBytes) should equal (hmac)
  }

  "Digest" should "be able to digest data with default parameters" in {
    assertDigest(digest data str toBytes)
  }

  "Digest" should "be able to digest data with specific algorithm" in {
    val alg = "SHA-1"
    assertDigest(digest data str withAlgorithm alg toBytes, alg = alg)
  }

  "Digest" should "be able to digest data with a stream handler" in {
    val out = new ByteArrayOutputStream()

    assertDigest(digest data str withStreamHandler copyHandler(out) toBytes)
    str.getBytes should equal (out.toByteArray)
  }

  "HMAC" should "be able to digest data with default parameters" in {
    val k = Generators.key()
    assertHMAC(k, hmac data str using k toBytes)
  }

  "HMAC" should "be able to digest data with specific algorithm" in {
    val k = Generators.key()
    val alg = "HmacSHA1"
    assertHMAC(k, hmac data str using k withAlgorithm alg toBytes, alg = alg)
  }

  "HMAC" should "be able to digest data with a stream handler" in {
    val k = Generators.key()
    val alg = "HmacSHA1"

    val out = new ByteArrayOutputStream()

    assertHMAC(k, hmac data str using k withAlgorithm alg withStreamHandler copyHandler(out) toBytes, alg = alg)
    str.getBytes should equal (out.toByteArray)
  }

}