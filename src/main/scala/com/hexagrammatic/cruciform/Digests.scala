package com.hexagrammatic.cruciform

import StreamUtils.FunctionFilterStream
import StreamUtils.NullStreamHandler
import StreamUtils.StreamHandler

import java.io.{InputStream, OutputStream}
import java.security.{DigestInputStream, Key, MessageDigest, Provider}

import javax.crypto.Mac


object Digests {

  val DefaultDigestAlgorithm = "SHA-256"
  val DefaultHMACAlgorithm = "HmacSHA256"

  /**
   * Takes data and creates a cryptographic digest from it.  The provided data is
   * converted to a stream using `StreamUtils.toStream` and copied through a digest
   * filter to calculate the digest.
   *
   * Callers may optionally provide a stream handler that can handle copy operation.
   * This handler must copy all of the data that is expected to be used to create the digest.
   *
   */
}

/**
 * Provides cryptographic hash extensions.
 */
trait Digests extends StreamConversions {

  class DigestOperation(
      stream: InputStream,
      algorithm: String = Digests.DefaultDigestAlgorithm,
      provider: Option[Any] = None,
      handler: StreamHandler = NullStreamHandler) extends Writeable {

    def withAlgorithm(algorithm: String): DigestOperation =
      new DigestOperation(stream, algorithm, provider, handler)

    def withProvider(provider: Any): DigestOperation =
      new DigestOperation(stream, algorithm, Option(provider), handler)

    def withStreamHandler(handler: StreamHandler): DigestOperation =
      new DigestOperation(stream, algorithm, provider, handler)

    def to[T <: OutputStream](out: T): T = {
      val md = provider match {
        case Some(value) =>
          value match {
            case p:Provider => MessageDigest getInstance(algorithm, p)
            case s => MessageDigest getInstance(algorithm, s.toString)
          }
        case None => MessageDigest getInstance(algorithm)
      }

      handler(new DigestInputStream(stream, md))
      out.write(md.digest)
      out
    }
  }

  class DigestAskForData {
    def data(stream: InputStream): DigestOperation = new DigestOperation(stream)
  }

  def digest: DigestAskForData = new DigestAskForData

  class HMACOperation(
      stream: InputStream,
      key: Key,
      algorithm: String = Digests.DefaultHMACAlgorithm,
      provider: Option[Any] = None,
      handler: StreamHandler = NullStreamHandler) extends Writeable {

    def withAlgorithm(algorithm: String): HMACOperation =
      new HMACOperation(stream, key, algorithm, provider, handler)

    def withProvider(provider: Any): HMACOperation =
      new HMACOperation(stream, key, algorithm, Option(provider), handler)

    def withStreamHandler(handler: StreamHandler): HMACOperation =
      new HMACOperation(stream, key, algorithm, provider, handler)

    def to[T <: OutputStream](out: T): T = {
      val mac = provider match {
        case Some(value) =>
          value match {
            case p:Provider => Mac getInstance(algorithm, p)
            case s => Mac getInstance(algorithm, s.toString)
          }
        case None => Mac getInstance(algorithm)
      }

      mac init(key)

      handler(
        new FunctionFilterStream(
          stream,
          (b: Byte) => mac update(b),
          Option((a: Array[Byte], off: Int, len: Int) => mac update(a, off, len))))

      out write(mac.doFinal)
      out
    }
  }

  class HMACAskForKey(stream: InputStream) {
    def using(key: Key): HMACOperation = new HMACOperation(stream, key)
  }

  class HMACAskForData(key: Key) {
    def data(stream: InputStream): HMACOperation = new HMACOperation(stream, key)
  }

  class HMACAskForDataOrKey {
    def data(stream: InputStream): HMACAskForKey = new HMACAskForKey(stream)
    def using(key: Key): HMACAskForData = new HMACAskForData(key)
  }

  def hmac: HMACAskForDataOrKey = new HMACAskForDataOrKey
}
