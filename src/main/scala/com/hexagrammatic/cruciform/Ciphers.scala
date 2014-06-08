package com.hexagrammatic.cruciform

import StreamUtils._

import java.io.InputStream
import java.io.IOException
import java.security._
import java.security.cert.Certificate

import javax.crypto.Cipher
import javax.crypto.CipherInputStream
import javax.crypto.spec.IvParameterSpec
import scala.Some
import java.util.concurrent.atomic.AtomicReference

/**
 * Provides functions to perform cryptographic operations.
 *
 * @author Bill Dimmick <me@billdimmick.com>
 */
object Ciphers {

  //Maps the default cipher type for the given key types
  private val cipherForKeyType = Map(
    "AES" -> "AES/CBC/PKCS5Padding",
    "DES" -> "DES/CBC/PKCS5Padding",
    "RSA" -> "RSA/ECB/PKCS1Padding")

  //Maps the default signature type for a given key type
  private val signatureForKeyType = Map(
    "RSA" -> "SHA256withRSA",
    "DSA" -> "SHA1withDSA")

  private def findAlgorithm(algorithm: Option[String], keyAlgorithm: String, map: Map[String, String]): String =
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

    val result = provider match {
      case Some(value) => {
        value match {
          case p: Provider => Cipher.getInstance(findAlgorithm(algorithm, key.getAlgorithm, cipherForKeyType), p)
          case s => Cipher.getInstance(findAlgorithm(algorithm, key.getAlgorithm, cipherForKeyType), s.toString)
        }
      }
      case None => Cipher.getInstance(findAlgorithm(algorithm, key.getAlgorithm, cipherForKeyType))
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

    provider match {
      case Some(value) => {
        value match {
          case p: Provider =>
            Signature.getInstance(findAlgorithm(algorithm, key.getAlgorithm, signatureForKeyType), p)
          case s =>
            Signature.getInstance(findAlgorithm(algorithm, key.getAlgorithm, signatureForKeyType), s.toString)
        }
      }
      case None => Signature.getInstance(findAlgorithm(algorithm, key.getAlgorithm, signatureForKeyType))
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
      case kp: Keypair => createCipher(algorithm, kp.publicKey, Cipher.ENCRYPT_MODE, provider)
    }

    Option(cipher.getIV) match {
      case Some(iv) => {
        initVectorHandler.getOrElse(
          {
            val alg = cipher.getAlgorithm
            throw new IllegalArgumentException("Algorithm $alg requires an IV handler to be provided.")
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
      case k: Key => createCipher(algorithm, k, Cipher.DECRYPT_MODE, provider, initVector)
      case kp: Keypair => createCipher(algorithm, kp.privateKey, Cipher.DECRYPT_MODE, provider, initVector)
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

    val signer = key match {
      case k: PrivateKey => {
        val result = createSignature(algorithm, k, provider)
        result.initSign(k)
        result
      }
      case kp: Keypair => {
        val result = createSignature(algorithm, kp.privateKey, provider)
        result.initSign(kp.privateKey)
        result
      }
    }

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

    val signer = key match {
      case k: PublicKey => {
        val result = createSignature(algorithm, k, provider)
        result.initVerify(k)
        result
      }
      case kp: Keypair => {
        val result = createSignature(algorithm, kp.publicKey, provider)
        result.initVerify(kp.publicKey)
        result
      }
      case c: Certificate => {
        val result = createSignature(algorithm, c.getPublicKey, provider)
        result.initVerify(c)
        result
      }
    }

    streamHandler(makeSigningFilterStream(data, signer))

    try {
      signer.verify(signature)
    } catch {
      case ex: SignatureException => false
    }
  }
}
