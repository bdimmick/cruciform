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

import java.io.ByteArrayOutputStream
import java.security.Key
import java.security.NoSuchAlgorithmException

import org.scalamock.scalatest.MockFactory
import org.scalatest.FlatSpec
import org.scalatest.Matchers


class CiphersSpec extends FlatSpec with Matchers with MockFactory with Ciphers with KeyGenerators {

  val str = "Hello World"

  def validateResults(ciphertext: Array[Byte], plaintext: Array[Byte]) {
    (str.getBytes) should not equal (ciphertext)
    (str.getBytes) should equal (plaintext)
  }

  "Ciphers" should "be able to use key and data in any order for encrypt and decrypt" in {
    val key = AES key
    val ivStream1 = new ByteArrayOutputStream()
    val ivStream2 = new ByteArrayOutputStream()

    val ciphertext1 = encrypt data str using key writeInitVectorTo ivStream1 asBytes
    val ciphertext2 = encrypt using key data str writeInitVectorTo ivStream2 asBytes

    val plaintext1 = decrypt data ciphertext1 using key withInitVector ivStream1.toByteArray asBytes
    val plaintext2 = decrypt using key data ciphertext2 withInitVector ivStream2.toByteArray asBytes

    (plaintext1) should equal (plaintext2)

    validateResults(ciphertext1, plaintext2)
    validateResults(ciphertext1, plaintext1)
    validateResults(ciphertext2, plaintext2)
    validateResults(ciphertext2, plaintext1)
  }

  "Ciphers" should "be able to perform AES encryption with defaults" in {
    val key = AES key
    val ivStream = new ByteArrayOutputStream()
    
    val ciphertext = encrypt data str using key writeInitVectorTo ivStream asBytes
    val plaintext = decrypt data ciphertext using key withInitVector ivStream.toByteArray asBytes

    validateResults(ciphertext, plaintext)
  }

  "Ciphers" should "be able to perform AES encryption with ECB without init vector" in {
    val alg = "AES/ECB/PKCS5Padding"
    val key = AES key

    val ciphertext = encrypt data str using key withAlgorithm alg asBytes
    val plaintext = decrypt data ciphertext using key withAlgorithm alg asBytes

    validateResults(ciphertext, plaintext)
  }

  "Ciphers" should "be able to perform DES encryption with defaults" in {
    val key = DES key
    val ivStream = new ByteArrayOutputStream()
    
    val ciphertext = encrypt data str using key writeInitVectorTo ivStream asBytes
    val plaintext = decrypt data ciphertext using key withInitVector ivStream.toByteArray asBytes

    validateResults(ciphertext, plaintext)
  }

  "Ciphers" should "throw an exception if an IV is created and no handler is specified" in {
    intercept[IllegalArgumentException] {
      encrypt data str using (AES key) withAlgorithm "AES/CBC/PKCS5Padding" to new ByteArrayOutputStream()
    }
  }

  "Ciphers" should "be able to perform RSA encryption" in {
    val keypair = RSA keypair

    val ciphertext = encrypt data str using keypair asBytes
    val plaintext = decrypt data ciphertext using keypair asBytes

    validateResults(ciphertext, plaintext)
  }

  "Ciphers" should "throw an exception with an illegal specified algorithm in encrypt" in {
    intercept[NoSuchAlgorithmException] {
      encrypt data str using (AES key) withAlgorithm "BAD" to new ByteArrayOutputStream()
    }
  }

  "Ciphers" should "throw an exception with an illegal derived algorithm in encrypt" in {
    val key = mock[Key]

    (key.getAlgorithm _) expects() returning("BAD") anyNumberOfTimes()

    intercept[NoSuchAlgorithmException] {
      encrypt data str using key to new ByteArrayOutputStream()
    }
  }

  "Ciphers" should "be able to sign and verify data with defaults" in {
    val keypair = RSA keypair

    val sig = sign data str using keypair asBytes

    // Valid verification with paired key
    (verify signature sig using keypair from str) should equal (true)

    // Invalid verification with different key
    (verify signature sig using (RSA keypair) from str) should equal (false)
  }

  "Ciphers" should "be able to sign and verify data with RSA and specifics" in {
    val keypair = RSA keypair
    val algorithm = "SHA1withRSA"

    val sig = sign data str using keypair withAlgorithm algorithm asBytes

    // Valid verification with paired key
    (verify signature sig using keypair withAlgorithm algorithm from str) should equal (true)

    // Invalid verification with different key
    (verify signature sig using (RSA keypair) withAlgorithm algorithm from str) should equal (false)

    // Invalid verification with different algorithm
    (verify signature sig using keypair withAlgorithm "MD5withRSA" from str) should equal (false)
  }

  "Ciphers" should "be able to use key and data in any order for sign and verify" in {
    val keypair = RSA keypair

    val sig1 = sign data str using keypair asBytes
    val sig2 = sign using keypair data str asBytes

    (verify signature sig1 using keypair from str) should equal (true)
    (verify signature sig2 using keypair from str) should equal (true)
    (verify using keypair signature sig1 from str) should equal (true)
  }
}