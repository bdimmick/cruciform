package com.hexagrammatic.cruciform

import java.io.{InputStreamReader, InputStream, OutputStreamWriter, OutputStream}
import java.security.Key
import java.security.KeyPair
import java.security.PublicKey
import java.security.PrivateKey

import javax.security.cert.Certificate

import org.bouncycastle.openssl.{PEMParser, PEMWriter}


trait Encoders extends StreamConversions {

  private class PEMEncoder(objs: AnyRef*) extends Writeable {
    def to[T <: OutputStream](out: T): T = {
      val writer = new PEMWriter(new OutputStreamWriter(out))
      objs.foreach((r:AnyRef) => writer.writeObject(r))
      writer.flush
      out
    }
  }

  class PEMCertificateEncoder(cert: Certificate) extends PEMEncoder(cert)
  class PEMKeyPairEncoder(pair: KeyPair) extends PEMEncoder(pair.getPublic, pair.getPrivate)
  class PEMKeyEncoder(key: Key) extends PEMEncoder(key)

  object PEM {
    def encode(cert: Certificate): PEMCertificateEncoder = new PEMCertificateEncoder(cert)
    def encode(pair: KeyPair): PEMKeyPairEncoder = new PEMKeyPairEncoder(pair)
    def encode(key: PublicKey): PEMKeyEncoder = new PEMKeyEncoder(key)
    def encode(key: PrivateKey): PEMKeyEncoder = new PEMKeyEncoder(key)

    def decode(in: InputStream): Unit = {
      val parser = new PEMParser(new InputStreamReader(in))
      parser.readObject
    }
  }
}
