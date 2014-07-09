/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package com.hexagrammatic.cruciform

import Digests._
import StreamUtils.copyHandler

import java.io.ByteArrayOutputStream
import java.security.Key
import java.security.MessageDigest

import javax.crypto.Mac

import org.scalatest.FlatSpec
import org.scalatest.Matchers


class DigestsSpec extends FlatSpec with Matchers with Digests with KeyGenerators {

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
    assertDigest(digest data str asBytes)
  }

  "Digest" should "be able to digest data with specific algorithm" in {
    val alg = "SHA-1"
    assertDigest(digest data str withAlgorithm alg asBytes, alg = alg)
  }

  "Digest" should "be able to digest data with a stream handler" in {
    val out = new ByteArrayOutputStream()

    assertDigest(digest data str withStreamHandler copyHandler(out) asBytes)
    (str.getBytes) should equal (out.toByteArray)
  }

  "HMAC" should "be able to digest data with default parameters" in {
    val k = AES key

    assertHMAC(k, hmac data str using k asBytes)
  }

  "HMAC" should "be able to digest data with specific algorithm" in {
    val k = AES key
    val alg = "HmacSHA1"
    assertHMAC(k, hmac data str using k withAlgorithm alg asBytes, alg = alg)
  }

  "HMAC" should "be able to digest data with a stream handler" in {
    val k = AES key
    val alg = "HmacSHA1"

    val out = new ByteArrayOutputStream()

    assertHMAC(k, hmac data str using k withAlgorithm alg withStreamHandler copyHandler(out) asBytes, alg = alg)
    (str.getBytes) should equal (out.toByteArray)
  }

  "HMAC" should "be able to use key and data in any order" in {
    val k = AES key
    val hmac1 = hmac data str using k asBytes
    val hmac2 = hmac using k data str asBytes

    (hmac1) should equal (hmac2)
  }

}