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

    val keyalg = key match {
      case k: Key => k.getAlgorithm
      case c: Certificate => c.getPublicKey.getAlgorithm
      case kp: Keypair => kp.algorithm
    }

    val cipher = createCipher(algorithm, keyalg, provider)

    key match {
      case k: Key => cipher.init(Cipher.ENCRYPT_MODE, k)
      case c: Certificate => cipher.init(Cipher.ENCRYPT_MODE, c)
      case kp: Keypair => cipher.init(Cipher.ENCRYPT_MODE, kp.publicKey)
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

    val keyalg = key match {
      case k: Key => k.getAlgorithm
      case kp: Keypair => kp.algorithm
    }

    val cipher = createCipher(algorithm, keyalg, provider)

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

  def sign(
    data: Any,
    key: Any,
    streamHandler: (InputStream) => Unit = StreamUtils.noopHandler,
    algorithm: Option[String] = None,
    provider: Option[Any] = None): Array[Byte] = {

    val keyalg = key match {
      case k: PrivateKey => k.getAlgorithm
      case kp: Keypair => kp.algorithm
    }

    val signer = createSignature(algorithm, keyalg, provider)

    key match {
      case k: PrivateKey => signer.initSign(k)
      case kp: Keypair => signer.initSign(kp.privateKey)
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

    val keyalg = key match {
      case k: PrivateKey => k.getAlgorithm
      case kp: Keypair => kp.algorithm
    }

    val signer = createSignature(algorithm, keyalg, provider)

    key match {
      case k: PublicKey => signer.initVerify(k)
      case c: Certificate => signer.initVerify(c)
      case kp: Keypair => signer.initVerify(kp.publicKey)
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