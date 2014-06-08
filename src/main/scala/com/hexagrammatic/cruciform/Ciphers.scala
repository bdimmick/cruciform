package com.hexagrammatic.cruciform

import StreamUtils.FunctionFilterStream
import StreamUtils.toStream

import java.io.InputStream
import java.security.Key
import java.security.KeyPair
import java.security.NoSuchAlgorithmException
import java.security.PrivateKey
import java.security.Provider
import java.security.PublicKey
import java.security.Signature
import java.security.SignatureException
import java.security.cert.Certificate

import javax.crypto.Cipher
import javax.crypto.CipherInputStream
import javax.crypto.spec.IvParameterSpec

/**
 * Provides functions to perform symmetric and asymmetric cryptographic operations.
 *
 */
object Ciphers {

  //Maps the default cipher type for the given key types
  private[this] val cipherForKeyType = Map(
    "AES" -> "AES/CBC/PKCS5Padding",
    "DES" -> "DES/CBC/PKCS5Padding",
    "RSA" -> "RSA/ECB/PKCS1Padding")

  //Maps the default signature type for a given key type
  private[this] val signatureForKeyType = Map(
    "RSA" -> "SHA256withRSA",
    "DSA" -> "SHA1withDSA")

  private def findAlgorithm(
    algorithm: Option[String],
    keyAlgorithm: String,
    map: Map[String, String]): String =
    algorithm.getOrElse(
      map.getOrElse(
        keyAlgorithm,
        throw new NoSuchAlgorithmException(s"Cipher not found for key algorithm $keyAlgorithm.")
      )
    )

  private def createCipher(
    algorithm: Option[String],
    key: Key,
    mode: Int,
    provider: Option[Any] = None,
    initVector: Option[Array[Byte]] = None): Cipher = {

    val foundAlgorithm = findAlgorithm(algorithm, key.getAlgorithm, cipherForKeyType)
    val result = provider match {
      case Some(value) => {
        value match {
          case p: Provider => Cipher.getInstance(foundAlgorithm, p)
          case s => Cipher.getInstance(foundAlgorithm, s.toString)
        }
      }
      case None => Cipher.getInstance(foundAlgorithm)
    }

    val spec = mode match {
      case Cipher.DECRYPT_MODE => {
        initVector match {
          case Some(iv) => new IvParameterSpec(iv)
          case None => null
        }
      }
      case _ => null
    }

    result.init(mode, key, spec)
    result
  }

  private def createSignature(
    algorithm: Option[String],
    key: Key,
    provider: Option[Any] = None): Signature = {

    val foundAlgorithm = findAlgorithm(algorithm, key.getAlgorithm, signatureForKeyType)
    provider match {
      case Some(value) => {
        value match {
          case p: Provider => Signature.getInstance(foundAlgorithm, p)
          case s => Signature.getInstance(foundAlgorithm, s.toString)
        }
      }
      case None => Signature.getInstance(foundAlgorithm)
    }
  }

  def encrypt(
    data: Any,
    key: Any,
    streamHandler: (InputStream) => Any,
    initVectorHandler: Option[(Array[Byte]) => Unit] = None,
    algorithm: Option[String] = None,
    provider: Option[Any] = None): Any = {

    val cipher = key match {
      case k: Key => createCipher(algorithm, k, Cipher.ENCRYPT_MODE, provider)
      case c: Certificate => createCipher(algorithm, c.getPublicKey, Cipher.ENCRYPT_MODE, provider)
      case kp: KeyPair => createCipher(algorithm, kp.getPublic, Cipher.ENCRYPT_MODE, provider)
    }

    Option(cipher.getIV) match {
      case Some(iv) => {
        initVectorHandler.getOrElse(
          {
            val msg = "Algorithm $cipher.getAlgorithm requires an IV handler to be provided."
            throw new IllegalArgumentException(msg)
          }
        )(iv)
      }
      case None =>
    }

    streamHandler(new CipherInputStream(toStream(data), cipher))
  }

  def decrypt(
    data: Any,
    key: Any,
    streamHandler: (InputStream) => Unit,
    initVector: Option[Array[Byte]] = None,
    algorithm: Option[String] = None,
    provider: Option[Any] = None): Unit = {

    val cipher = key match {
      case k: Key =>
        createCipher(algorithm, k, Cipher.DECRYPT_MODE, provider, initVector)
      case kp: KeyPair =>
        createCipher(algorithm, kp.getPrivate, Cipher.DECRYPT_MODE, provider, initVector)
    }

    streamHandler(new CipherInputStream(toStream(data), cipher))
  }

  private def makeSigningFilterStream(data: Any, signer: Signature): FunctionFilterStream = {
    new FunctionFilterStream(
      toStream(data),
      (b: Byte) => signer.update(b),
      Option((a: Array[Byte], off: Int, len: Int) => signer.update(a, off, len))
    )
  }

  def sign(
    data: Any,
    key: Any,
    streamHandler: (InputStream) => Unit = StreamUtils.noopHandler,
    algorithm: Option[String] = None,
    provider: Option[Any] = None): Array[Byte] = {

    val (signer, signKey) = key match {
      case k: PrivateKey => (createSignature(algorithm, k, provider), k)
      case kp: KeyPair => (createSignature(algorithm, kp.getPrivate, provider), kp.getPrivate)
    }

    signer.initSign(signKey)
    streamHandler(makeSigningFilterStream(data, signer))
    signer.sign
  }

  def verify(
    data: Any,
    key: Any,
    signature: Array[Byte],
    streamHandler: (InputStream) => Unit = StreamUtils.noopHandler,
    algorithm: Option[String] = None,
    provider: Option[Any] = None): Boolean = {

    val (signer, verifyKey) = key match {
      case k: PublicKey => (createSignature(algorithm, k, provider), k)
      case kp: KeyPair => (createSignature(algorithm, kp.getPublic, provider), kp.getPublic)
      case c: Certificate => (createSignature(algorithm, c.getPublicKey, provider), c.getPublicKey)
    }

    signer.initVerify(verifyKey)
    streamHandler(makeSigningFilterStream(data, signer))

    try {
      signer.verify(signature)
    } catch {
      case ex: SignatureException => false
    }
  }
}
