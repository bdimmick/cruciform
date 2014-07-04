package com.hexagrammatic.cruciform

import java.security.Key
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.Provider

import javax.crypto.KeyGenerator


trait KeyGenerators {
  class Strength(val value: Int) { def bit: Strength = this }
  implicit def strengthFromInt(str: Int): Strength = new Strength(str)

  sealed class SymmetricType(
      val algorithm: String,
      val strength: Option[Strength] = None,
      val provider: Option[Any] = None) {

    def strength(strength: Strength): SymmetricType = new SymmetricType(algorithm, Option(strength), provider)
    def withProvider(provider: Any): SymmetricType = new SymmetricType(algorithm, strength, Option(provider))
    def key: Key = {
      val generator = provider match {
        case None => KeyGenerator.getInstance(algorithm)
        case Some(value) => {
          value match {
            case p: Provider => KeyGenerator.getInstance(algorithm, p)
            case str => KeyGenerator.getInstance(algorithm, str.toString)
          }
        }
      }

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
      val provider: Option[Any] = None) {

    def strength(strength: Strength): AsymmetricType = new AsymmetricType(algorithm, Option(strength), provider)
    def withProvider(provider: Any): AsymmetricType = new AsymmetricType(algorithm, strength, Option(provider))
    def keypair: KeyPair = {
      val generator = provider match {
        case None => KeyPairGenerator.getInstance(algorithm)
        case Some(value) => {
          value match {
            case p: Provider => KeyPairGenerator.getInstance(algorithm, p)
            case str => KeyPairGenerator.getInstance(algorithm, str.toString)
          }
        }
      }

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