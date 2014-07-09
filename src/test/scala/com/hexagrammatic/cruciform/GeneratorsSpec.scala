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

  "Generators" should "be able to be extended easily" in {
    val Rijndael = new SymmetricType("Rijndael")

    Rijndael key
  }
}