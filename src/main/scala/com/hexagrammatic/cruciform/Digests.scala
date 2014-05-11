package com.hexagrammatic.cruciform

import java.io.ByteArrayInputStream
import java.io.FilterInputStream
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
    handler(new HMACInputStream(StreamUtils.toStream(data), mac))
    mac.doFinal
  }

  private class HMACInputStream(in: InputStream, hmac: Mac) extends FilterInputStream(in) {

    override def read: Int = {
      val ch = in.read()
      if (ch != -1) {
        hmac.update(ch.byteValue)
      }
      ch
    }

    override def read(b: Array[Byte], off: Int, len: Int): Int = {
      val result = in.read(b, off, len)
      if (result > 0) {
        hmac.update(b, off, result)
      }
      result
    }
  }
}