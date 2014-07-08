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

import java.security.Key
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.Provider

import javax.crypto.KeyGenerator


trait KeyGenerators extends Core {
  class Strength(val value: Int) { def bit: Strength = this }
  implicit def strengthFromInt(str: Int): Strength = new Strength(str)

  sealed class SymmetricType(
      val algorithm: String,
      val strength: Option[Strength] = None,
      val provider: OptionalProvider = DefaultProvider) {

    def strength(strength: Strength): SymmetricType = new SymmetricType(algorithm, Option(strength), provider)

    def withProvider(provider: OptionalProvider): SymmetricType = new SymmetricType(algorithm, strength, provider)

    def key: Key = {
      val generator = fromProvider[KeyGenerator](
        provider,
        (p: Provider) => KeyGenerator getInstance(algorithm, p),
        (s: String) => KeyGenerator getInstance(algorithm, s)
      )

      strength match {
        case Some(str) => generator.init(str.value)
        case None =>
      }

      generator.generateKey
    }
  }

  sealed class AsymmetricType(
      val algorithm: String,
      val strength: Option[Strength] = None,
      val provider: OptionalProvider = DefaultProvider) {

    def strength(strength: Strength): AsymmetricType = new AsymmetricType(algorithm, Option(strength), provider)

    def withProvider(provider: OptionalProvider): AsymmetricType = new AsymmetricType(algorithm, strength, provider)

    def keypair: KeyPair = {
      val generator = fromProvider[KeyPairGenerator](
        provider,
        (p: Provider) => KeyPairGenerator getInstance(algorithm, p),
        (s: String) => KeyPairGenerator getInstance(algorithm, s)
      )

      strength match {
        case Some(str) => generator.initialize(str.value)
        case None =>
      }

      generator.generateKeyPair
    }
  }

  object AES extends SymmetricType("AES")
  object Blowfish extends SymmetricType("Blowfish")
  object DES extends SymmetricType("DES")

  object DSA extends AsymmetricType("DSA")
  object RSA extends AsymmetricType("RSA")
}