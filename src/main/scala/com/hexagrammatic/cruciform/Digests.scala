package com.hexagrammatic.cruciform

import StreamUtils.FunctionFilterStream
import StreamUtils.NullStreamHandler
import StreamUtils.StreamHandler
import StreamUtils.toStream

import java.io.{InputStream, OutputStream}
import java.security.DigestInputStream
import java.security.Key
import java.security.MessageDigest
import java.security.Provider

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
   * @param data the data from which to create the cryptographic hash
   * @param algorithm the algorithm to use; defaults to SHA-256
   * @param provider the JCE provider to use for the digest algorithm
   * @param streamHandler handler for the data stream; defaults to a no-op handler
   * @return the cryptographic hash as an array of bytes
   */
}

/**
 * Provides cryptographic hash functions.
 */
trait Digests extends StreamConversions {

  class Digest(
      _stream: InputStream,
      _algorithm: String = Digests.DefaultDigestAlgorithm,
      _provider: Option[Any] = None,
      _handler: StreamHandler = NullStreamHandler) extends Writeable {

    def algorithm(algorithm: String): Digest =
      new Digest(this._stream, algorithm, this._provider, this._handler)

    def provider(provider: Any): Digest =
      new Digest(this._stream, this._algorithm, Option(provider), this._handler)

    def streamHandler(handler: StreamHandler): Digest =
      new Digest(this._stream, this._algorithm, this._provider, handler)

    def to[T <: OutputStream](out: T): T = {
      val md = _provider match {
        case Some(value) =>
          value match {
            case p:Provider => MessageDigest.getInstance(_algorithm, p)
            case s => MessageDigest.getInstance(_algorithm, s.toString)
          }
        case None => MessageDigest.getInstance(_algorithm)
      }

      _handler(new DigestInputStream(_stream, md))
      out.write(md.digest)
      out
    }
  }

  class DigestDataNext {
    def data(stream: InputStream): Digest = new Digest(stream)
  }

  class HMAC(
      _stream: InputStream,
      _key: Key,
      _algorithm: String = Digests.DefaultHMACAlgorithm,
      _provider: Option[Any] = None,
      _handler: StreamHandler = NullStreamHandler) extends Writeable {

    def algorithm(algorithm: String): HMAC =
      new HMAC(this._stream, this._key, algorithm, this._provider, this._handler)

    def provider(provider: Any): HMAC =
      new HMAC(this._stream, this._key, this._algorithm, Option(provider), this._handler)

    def streamHandler(handler: StreamHandler): HMAC =
      new HMAC(this._stream, this._key, this._algorithm, this._provider, handler)

    def to[T <: OutputStream](out: T): T = {
      val mac = _provider match {
        case Some(value) =>
          value match {
            case p:Provider => Mac.getInstance(_algorithm, p)
            case s => Mac.getInstance(_algorithm, s.toString)
          }
        case None => Mac.getInstance(_algorithm)
      }

      mac.init(_key)

      _handler(
        new FunctionFilterStream(
          _stream,
          (b: Byte) => mac.update(b),
          Option((a: Array[Byte], off: Int, len: Int) => mac.update(a, off, len))))

      out.write(mac.doFinal)
      out
    }
  }

  class HMACKeyNext(stream: InputStream) {
    def using(key: Key): HMAC = new HMAC(stream, key)
  }

  class HMACDataNext {
    def data(stream: InputStream): HMACKeyNext = new HMACKeyNext(stream)
  }

  def digest: DigestDataNext = new DigestDataNext
  def hmac: HMACDataNext = new HMACDataNext
}
