package com.hexagrammatic.cruciform

import StreamUtils._

import java.io.InputStream
import java.security.Key
import java.security.KeyPair
import java.security.PrivateKey
import java.security.Provider
import java.security.PublicKey
import java.security.cert.Certificate
import java.security.spec.AlgorithmParameterSpec

import javax.crypto.Cipher
import javax.crypto.CipherInputStream
import javax.crypto.spec.IvParameterSpec


object Ciphers {

  private val algorithmsToTransforms = Map(
    "AES" -> "AES/CBC/PKCS5Padding",
    "DES" -> "DES/CBC/PKCS5Padding",
    "RSA" -> "RSA/ECB/PKCS1Padding")

  class TranformationNotFound(m: String) extends Exception(m)

  private val transformationNotFound = (a: String) => {
    throw new TranformationNotFound(s"Transformation not found for algorithm $a.")
  }

  private def findTransformation(transformation: Option[String], algorithm: String): String =
    transformation.getOrElse(algorithmsToTransforms.getOrElse(algorithm, transformationNotFound(algorithm)))

  private def createCipher(
    transformation: Option[String],
    algorithm: String,
    provider: Option[Any] = None): Cipher = {

    provider match {
      case Some(value) => {
        value match {
          case p: Provider => Cipher.getInstance(findTransformation(transformation, algorithm), p)
          case s => Cipher.getInstance(findTransformation(transformation, algorithm), s.toString)
        }
      }
      case None => Cipher.getInstance(findTransformation(transformation, algorithm))
    }
  }

  def encrypt(
    data: Any,
    key: Any,
    streamHandler: (InputStream) => Unit,
    initVectorHandler: Option[(Array[Byte]) => Unit] = None,
    transformation: Option[String] = None,
    provider: Option[Any] = None) {

    val alg = key match {
      case k: Key => k.getAlgorithm
      case c: Certificate => c.getPublicKey.getAlgorithm
      case kp: Keypair => kp.algorithm
    }

    val cipher = createCipher(transformation, alg, provider)

    key match {
      case k: Key => cipher.init(Cipher.ENCRYPT_MODE, k)
      case c: Certificate => cipher.init(Cipher.ENCRYPT_MODE, c)
      case kp: Keypair => cipher.init(Cipher.ENCRYPT_MODE, kp.publicKey)
    }

    if (cipher.getIV() != null) {
      initVectorHandler match {
        case Some(handler) => handler(cipher.getIV)
        case None => throw new IllegalArgumentException()
      }
    }

    streamHandler(new CipherInputStream(toStream(data), cipher))
  }

  def decrypt(
    data: Any,
    key: Any,
    streamHandler: (InputStream) => Unit,
    initVector: Option[Array[Byte]] = None,
    transformation: Option[String] = None,
    provider: Option[Any] = None) {

    val alg = key match {
      case k: Key => k.getAlgorithm
      case kp: Keypair => kp.algorithm
    }

    val cipher = createCipher(transformation, alg, provider)

    val spec = initVector match {
      case Some(iv) => new IvParameterSpec(iv)
      case None => null
    }

    key match {
      case k: Key => cipher.init(Cipher.DECRYPT_MODE, k, spec)
      case kp: Keypair => cipher.init(Cipher.DECRYPT_MODE, kp.privateKey, spec)
    }

    streamHandler(new CipherInputStream(toStream(data), cipher))
  }

  def sign(data: Any, key: PrivateKey): Array[Byte] = {
    Array[Byte]()
  }

  def verify(data: Any, key: PublicKey, signature: Array[Byte]): Boolean = {
    false
  }

}