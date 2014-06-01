package com.hexagrammatic.cruciform

import java.security.Key
import java.security.KeyPairGenerator
import java.security.Provider

/**
 *
 */
object Generators {

  object Constants {
    val DEFAULT_SYMMETRIC_ALG = "AES"
    val DEFAULT_ASYMMETRIC_ALG = "RSA"
  }

  def key(
    algorithm: String = Constants.DEFAULT_SYMMETRIC_ALG,
    strength: Option[Int] = None,
    provider: Option[Any] = None): Key =
    new SymmetricKeyGenerator(algorithm, strength, provider).generate

  def keypair(
    algorithm: String = Constants.DEFAULT_ASYMMETRIC_ALG,
    strength: Option[Int] = None,
    provider: Option[Any] = None): Keypair =
    new AsymmetricKeyGenerator(algorithm, strength, provider).generate
}

/**
 *
 */
class SymmetricKeyGenerator(
  algorithm: String = Generators.Constants.DEFAULT_SYMMETRIC_ALG,
  strength: Option[Int] = None,
  provider: Option[Any] = None) {

  private val generator = provider match {
    case None => javax.crypto.KeyGenerator.getInstance(algorithm)
    case Some(value) => {
      value match {
        case p: Provider => javax.crypto.KeyGenerator.getInstance(algorithm, p)
        case str => javax.crypto.KeyGenerator.getInstance(algorithm, str.toString)
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
  algorithm: String = Generators.Constants.DEFAULT_ASYMMETRIC_ALG,
  strength: Option[Int] = None,
  provider: Option[Any] = None) {

  private val generator = provider match {
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

  def generate: Keypair = new Keypair(generator.generateKeyPair)
}