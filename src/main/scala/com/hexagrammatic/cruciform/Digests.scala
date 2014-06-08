package com.hexagrammatic.cruciform

import StreamUtils.FunctionFilterStream

import java.io.InputStream
import java.security.DigestInputStream
import java.security.Key
import java.security.MessageDigest
import java.security.Provider

import javax.crypto.Mac


object Digests {

  object Constants {
    val DEFAULT_DIGEST_ALGORITHM = "SHA-256"
    val DEFAULT_HMAC_ALGORITHM = "HmacSHA256"
  }

  def digest(
    data: Any,
    algorithm: String = Constants.DEFAULT_DIGEST_ALGORITHM,
    provider: Option[Any] = None,
    handler: (InputStream) => Unit = StreamUtils.noopHandler): Array[Byte] = {

    val md = provider match {
      case Some(value) => 
        value match {
          case p:Provider => MessageDigest.getInstance(algorithm, p)
          case s => MessageDigest.getInstance(algorithm, s.toString)
        }      
      case None => MessageDigest.getInstance(algorithm)
    }

    handler(new DigestInputStream(StreamUtils.toStream(data), md))
    md.digest
  }

  def hmac(
    data: Any,
    key: Key,
    algorithm: String = Constants.DEFAULT_HMAC_ALGORITHM,
    provider: Option[Any] = None,
    handler: (InputStream) => Unit = StreamUtils.noopHandler): Array[Byte] = {

    val mac = provider match {
      case Some(value) => 
        value match {
          case p:Provider => Mac.getInstance(algorithm, p)
          case s => Mac.getInstance(algorithm, s.toString)
        }              
      case None => Mac.getInstance(algorithm)
    }

    mac.init(key)

    handler(
      new FunctionFilterStream(
        StreamUtils.toStream(data),
        (b: Byte) => mac.update(b),
        Option((a: Array[Byte], off: Int, len: Int) => mac.update(a, off, len))))

    mac.doFinal
  }
}