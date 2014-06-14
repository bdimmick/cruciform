package com.hexagrammatic.cruciform

import StreamUtils.FunctionFilterStream
import StreamUtils.NullStreamHandler
import StreamUtils.toStream

import java.io.InputStream
import java.security.DigestInputStream
import java.security.Key
import java.security.MessageDigest
import java.security.Provider

import javax.crypto.Mac


/**
 * Provides cryptographic hash functions.
 */
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
  def digest(
    data: Any,
    algorithm: String = DefaultDigestAlgorithm,
    provider: Option[Any] = None,
    streamHandler: (InputStream) => Unit = NullStreamHandler): Array[Byte] = {

    val md = provider match {
      case Some(value) => 
        value match {
          case p:Provider => MessageDigest.getInstance(algorithm, p)
          case s => MessageDigest.getInstance(algorithm, s.toString)
        }      
      case None => MessageDigest.getInstance(algorithm)
    }

    streamHandler(new DigestInputStream(toStream(data), md))
    md.digest
  }

  /**
   *
   *
   * @param data
   * @param key
   * @param algorithm
   * @param provider
   * @param streamHandler
   * @return
   */
  def hmac(
    data: Any,
    key: Key,
    algorithm: String = DefaultHMACAlgorithm,
    provider: Option[Any] = None,
    streamHandler: (InputStream) => Unit = NullStreamHandler): Array[Byte] = {

    val mac = provider match {
      case Some(value) => 
        value match {
          case p:Provider => Mac.getInstance(algorithm, p)
          case s => Mac.getInstance(algorithm, s.toString)
        }              
      case None => Mac.getInstance(algorithm)
    }

    mac.init(key)

    streamHandler(
      new FunctionFilterStream(
        toStream(data),
        (b: Byte) => mac.update(b),
        Option((a: Array[Byte], off: Int, len: Int) => mac.update(a, off, len))))

    mac.doFinal
  }
}