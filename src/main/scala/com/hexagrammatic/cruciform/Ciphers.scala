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


object Ciphers {

  private val cipherForKeyType = Map(
    "AES" -> "AES/CBC/PKCS5Padding",
    "DES" -> "DES/CBC/PKCS5Padding",
    "RSA" -> "RSA/ECB/PKCS1Padding")

  private val signatureForKeyType = Map(
    "RSA" -> "SHA256withRSA",
    "DSA" -> "SHA1withDSA")

  private def noopIVHandler(iv: Array[Byte]): Any = {}

  private def findAlgorithm(algorithm: Option[String], keyAlgorithm: String, map: Map[String, String]): String =
    algorithm.getOrElse(
      map.getOrElse(
        keyAlgorithm,
        throw new NoSuchAlgorithmException(s"Cipher not found for key algorithm $keyAlgorithm.")
      )
    )

  private def createCipher(
    algorithm: Option[String],
    keyAlgorithm: String,
    provider: Option[Any] = None): Cipher = {

    provider match {
      case Some(value) => {
        value match {
          case p: Provider => Cipher.getInstance(findAlgorithm(algorithm, keyAlgorithm, cipherForKeyType), p)
          case s => Cipher.getInstance(findAlgorithm(algorithm, keyAlgorithm, cipherForKeyType), s.toString)
        }
      }
      case None => Cipher.getInstance(findAlgorithm(algorithm, keyAlgorithm, cipherForKeyType))
    }
  }

  private def createSignature(
    algorithm: Option[String],
    keyAlgorithm: String,
    provider: Option[Any] = None): Signature = {

    provider match {
      case Some(value) => {
        value match {
          case p: Provider => Signature.getInstance(findAlgorithm(algorithm, keyAlgorithm, signatureForKeyType), p)
          case s => Signature.getInstance(findAlgorithm(algorithm, keyAlgorithm, signatureForKeyType), s.toString)
        }
      }
      case None => Signature.getInstance(findAlgorithm(algorithm, keyAlgorithm, signatureForKeyType))
    }
  }

  def encrypt(
    data: Any,
    key: Any,
    streamHandler: (InputStream) => Any,
    initVectorHandler: (Array[Byte]) => Any = noopIVHandler,
    algorithm: Option[String] = None,
    provider: Option[Any] = None): Unit = {

    val cipher = key match {
      case k: Key => {
        val result = createCipher(algorithm, k.getAlgorithm, provider)
        result.init(Cipher.ENCRYPT_MODE, k)
        result
      }
      case c: Certificate => {
        val result = createCipher(algorithm, c.getPublicKey.getAlgorithm, provider)
        result.init(Cipher.ENCRYPT_MODE, c.getPublicKey)
        result
      }
      case kp: Keypair => {
        val result = createCipher(algorithm, kp.algorithm, provider)
        result.init(Cipher.ENCRYPT_MODE, kp.publicKey)
        result
      }
    }

    if (cipher.getIV != null) initVectorHandler(cipher.getIV)

    streamHandler(new CipherInputStream(toStream(data), cipher))
  }

  def decrypt(
    data: Any,
    key: Any,
    streamHandler: (InputStream) => Unit,
    initVector: Option[Array[Byte]] = None,
    algorithm: Option[String] = None,
    provider: Option[Any] = None): Unit = {

    val spec = initVector match {
      case Some(iv) => new IvParameterSpec(iv)
      case None => null
    }

    val cipher = key match {
      case k: Key => {
        val result = createCipher(algorithm, k.getAlgorithm, provider)
        result.init(Cipher.DECRYPT_MODE, k, spec)
        result
      }
      case kp: Keypair => {
        val result = createCipher(algorithm, kp.algorithm, provider)
        result.init(Cipher.DECRYPT_MODE, kp.privateKey, spec)
        result
      }
    }

    streamHandler(new CipherInputStream(toStream(data), cipher))
  }

  def sign(
    data: Any,
    key: Any,
    streamHandler: (InputStream) => Unit = StreamUtils.noopHandler,
    algorithm: Option[String] = None,
    provider: Option[Any] = None): Array[Byte] = {

    val signer = key match {
      case k: PrivateKey => {
        val result = createSignature(algorithm, k.getAlgorithm, provider)
        result.initSign(k)
        result
      }
      case kp: Keypair => {
        val result = createSignature(algorithm, kp.algorithm, provider)
        result.initSign(kp.privateKey)
        result
      }
    }

    streamHandler(
      new FunctionFilterStream(
        toStream(data),
        (b: Byte) => signer.update(b),
        Option((a: Array[Byte], off: Int, len: Int) => signer.update(a, off, len))
      )
    )

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
        val result = createSignature(algorithm, k.getAlgorithm, provider)
        result.initVerify(k)
        result
      }
      case kp: Keypair => {
        val result = createSignature(algorithm, kp.algorithm, provider)
        result.initVerify(kp.publicKey)
        result
      }
      case c: Certificate => {
        val result = createSignature(algorithm, c.getPublicKey.getAlgorithm, provider)
        result.initVerify(c)
        result
      }
    }

    streamHandler(
      new FunctionFilterStream(
        toStream(data),
        (b: Byte) => signer.update(b),
        Option((a: Array[Byte], off: Int, len: Int) => signer.update(a, off, len))
      )
    )

    try {
      signer.verify(signature)
    } catch {
      case ex: SignatureException => false
    }
  }
}

//case class Signature() extends Serializable