package com.hexagrammatic.cruciform

import StreamUtils.copyHandler
import StreamUtils.FunctionFilterStream
import StreamUtils.NullStreamHandler

import java.io.{ByteArrayOutputStream, InputStream, OutputStream}
import java.security._
import java.security.cert.Certificate

import javax.crypto.Cipher
import javax.crypto.Cipher._
import javax.crypto.CipherInputStream
import javax.crypto.spec.IvParameterSpec


trait Ciphers extends StreamConversions {

  //Maps the default cipher type for a given key type
  private[this] val CipherForKeyType = Map(
    "AES" -> "AES/CBC/PKCS5Padding",
    "DES" -> "DES/CBC/PKCS5Padding",
    "RSA" -> "RSA/ECB/PKCS1Padding")

  //Maps the default signature type for a given key type
  private[this] val SignatureForKeyType = Map(
    "RSA" -> "SHA256withRSA",
    "DSA" -> "SHA1withDSA")

  private def algorithmForKey(key: Key, map: Map[String, String]): String =
    map getOrElse(key.getAlgorithm,
      throw new NoSuchAlgorithmException(s"Cipher not found for key algorithm " + key.getAlgorithm))

  def createCipher(algorithm: Option[String], key: Key, provider: Option[Any] = None): Cipher = {
    val foundAlgorithm = algorithm getOrElse algorithmForKey(key, CipherForKeyType)
    provider match {
      case Some(value) => {
        value match {
          case p: Provider => Cipher getInstance(foundAlgorithm, p)
          case s => Cipher getInstance(foundAlgorithm, s.toString)
        }
      }
      case None => Cipher getInstance(foundAlgorithm)
    }
  }

  private def createSignature(algorithm: Option[String], key: Key, provider: Option[Any] = None): Signature = {
    val foundAlgorithm = algorithm getOrElse algorithmForKey(key, SignatureForKeyType)
    provider match {
      case Some(value) => {
        value match {
          case p: Provider => Signature getInstance(foundAlgorithm, p)
          case s => Signature getInstance(foundAlgorithm, s.toString)
        }
      }
      case None => Signature getInstance(foundAlgorithm)
    }
  }

  private def makeSigningFilterStream(data: InputStream, signer: Signature): FunctionFilterStream = {
    new FunctionFilterStream(
      data,
      (b: Byte) => signer.update(b),
      Option((a: Array[Byte], off: Int, len: Int) => signer.update(a, off, len))
    )
  }

  class EncryptOperation(
      data: InputStream,
      key: Key,
      initVectorHandler: Option[(Array[Byte]) => Any] = None,
      algorithm: Option[String] = None,
      provider: Option[Any] = None) extends Writeable {

    def storeInitVectorWith(f: (Array[Byte] => Any)): EncryptOperation =
      new EncryptOperation(data, key, Option(f), algorithm, provider)

    def to[T <: OutputStream](out: T): T = {
      val cipher = createCipher(algorithm, key, provider)
      cipher init(ENCRYPT_MODE, key)

      // TODO(bdimmick): Can we ensure that this is always provided if the algorithm requires it?
      Option(cipher.getIV) match {
        case Some(iv) => {
          initVectorHandler match {
            case Some(handler) => handler(iv)
            case None =>
              throw new IllegalArgumentException(
                "Algorithm '" + cipher.getAlgorithm + " provides init vector but not init vector handler supplied.")
          }
        }
        case None =>
      }

      copyHandler(out)(new CipherInputStream(data, cipher))
      out
    }

    def withAlgorithm(algorithm: String): EncryptOperation =
      new EncryptOperation(data, key, initVectorHandler, Option(algorithm), provider)

    def withProvider(provider: Any): EncryptOperation =
      new EncryptOperation(data, key, initVectorHandler, algorithm, Option(provider))

    def writeInitVectorTo(out: OutputStream): EncryptOperation =
      storeInitVectorWith((iv:Array[Byte]) => out.write(iv))
  }

  class EncryptAskForKey(data: InputStream) {
    def using(cert: Certificate): EncryptOperation = this using (cert.getPublicKey)
    def using(key: Key): EncryptOperation = new EncryptOperation(data, key)
    def using(pair: KeyPair): EncryptOperation = this using (pair.getPublic)
  }

  class EncryptAskForData {
    def data(data: InputStream): EncryptAskForKey = new EncryptAskForKey(data)
  }

  def encrypt: EncryptAskForData = new EncryptAskForData

  class DecryptOperation(
      data: InputStream,
      key: Key,
      initVector: Option[Array[Byte]] = None,
      algorithm: Option[String] = None,
      provider: Option[Any] = None) extends Writeable {

    def to[T <: OutputStream](out: T): T = {
      val cipher = createCipher(algorithm, key, provider)
      val spec = initVector match {
        case Some(iv) => new IvParameterSpec(iv)
        case None => null
      }

      cipher init(DECRYPT_MODE, key, spec)

      copyHandler(out)(new CipherInputStream(data, cipher))
      out
    }

    def withAlgorithm(algorithm: String): DecryptOperation =
      new DecryptOperation(data, key, initVector, Option(algorithm), provider)

    def withInitVector(iv: Array[Byte]): DecryptOperation =
      new DecryptOperation(data, key, Option(iv), algorithm, provider)

    def withProvider(provider: Any): DecryptOperation =
      new DecryptOperation(data, key, initVector, algorithm, Option(provider))
  }

  class DecryptAskForKey(data: InputStream) {
    def using(key: Key): DecryptOperation = new DecryptOperation(data, key)
    def using(pair: KeyPair): DecryptOperation = this using pair.getPrivate
  }

  class DecryptAskForData {
    def data(data: InputStream): DecryptAskForKey = new DecryptAskForKey(data)
  }

  def decrypt: DecryptAskForData = new DecryptAskForData

  class SignOperation(
       data: InputStream,
       key: PrivateKey,
       algorithm: Option[String] = None,
       provider: Option[Any] = None) extends Writeable {

    def to[T <: OutputStream](out: T): T = {
      val signer = createSignature(algorithm, key, provider)
      signer initSign(key)
      NullStreamHandler(makeSigningFilterStream(data, signer))

      out write(signer.sign)
      out
    }

    def withAlgorithm(algorithm: String): SignOperation =
      new SignOperation(data, key, Option(algorithm), provider)

    def withProvider(provider: Any): SignOperation =
      new SignOperation(data, key, algorithm, Option(provider))
  }

  class SignAskForKey(data: InputStream) {
    def using(key: PrivateKey): SignOperation = new SignOperation(data, key)
    def using(pair: KeyPair): SignOperation = this using pair.getPrivate
  }

  class SignAskForData {
    def data(data: InputStream): SignAskForKey = new SignAskForKey(data)
  }

  def sign: SignAskForData = new SignAskForData

  class VerifyOperation(
    signature: InputStream,
    key: PublicKey,
    algorithm: Option[String] = None,
    provider: Option[Any] = None) {

    def from(data: InputStream): Boolean = {
      val sigbytes = new ByteArrayOutputStream
      val signer = createSignature(algorithm, key, provider)

      copyHandler(sigbytes)(signature)
      signer initVerify(key)
      NullStreamHandler(makeSigningFilterStream(data, signer))

      try {
        signer verify(sigbytes.toByteArray)
      } catch {
        case ex: SignatureException => false
      }
    }

    def withAlgorithm(algorithm: String): VerifyOperation =
      new VerifyOperation(signature, key, Option(algorithm), provider)

    def withProvider(provider: Any): VerifyOperation =
      new VerifyOperation(signature, key, algorithm, Option(provider))

  }

  class VerifyAskForKey(signature: InputStream) {
    def using(cert: Certificate): VerifyOperation = this using cert.getPublicKey
    def using(key: PublicKey): VerifyOperation = new VerifyOperation(signature, key)
    def using(pair: KeyPair): VerifyOperation = this using pair.getPublic
  }

  class VerifyAskForSignature {
    def signature(signature: InputStream): VerifyAskForKey = new VerifyAskForKey(signature)
  }

  def verify: VerifyAskForSignature = new VerifyAskForSignature
}