package com.hexagrammatic.cruciform

import java.security.Key
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.Provider

import javax.crypto.KeyGenerator


/**
 *
 */
object Generators {

  val DefaultAsymmetricAlgorithm = "RSA"
  val DefaultSymmetricAlgorithm = "AES"

  def key(
    algorithm: String = DefaultSymmetricAlgorithm,
    strength: Option[Int] = None,
    provider: Option[Any] = None): Key =
    new SymmetricKeyGenerator(algorithm, strength, provider).generate

  def keypair(
    algorithm: String = DefaultAsymmetricAlgorithm,
    strength: Option[Int] = None,
    provider: Option[Any] = None): KeyPair =
    new AsymmetricKeyGenerator(algorithm, strength, provider).generate
}

import Generators.DefaultAsymmetricAlgorithm
import Generators.DefaultSymmetricAlgorithm

/**
 *
 */
class SymmetricKeyGenerator(
  algorithm: String = DefaultSymmetricAlgorithm,
  strength: Option[Int] = None,
  provider: Option[Any] = None) {

  private [this] val generator = provider match {
    case None => KeyGenerator.getInstance(algorithm)
    case Some(value) => {
      value match {
        case p: Provider => KeyGenerator.getInstance(algorithm, p)
        case str => KeyGenerator.getInstance(algorithm, str.toString)
      }
    }
  }

  {
    strength match {
      case Some(str) => generator.init(str)
      case None =>
    }
  }

  def generate: Key = generator.generateKey
}

/**
 *
 */
class AsymmetricKeyGenerator(
  algorithm: String = DefaultAsymmetricAlgorithm,
  strength: Option[Int] = None,
  provider: Option[Any] = None) {

  private [this] val generator = provider match {
    case None => KeyPairGenerator.getInstance(algorithm)
    case Some(value) => {
      value match {
        case p: Provider => KeyPairGenerator.getInstance(algorithm, p)
        case str => KeyPairGenerator.getInstance(algorithm, str.toString)
      }
    }
  }

  {
    strength match {
      case Some(str) => generator.initialize(str)
      case None =>
    }
  }

  def generate: KeyPair = generator.generateKeyPair
}