package com.hexagrammatic.cruciform

import java.io.{InputStreamReader, InputStream, OutputStreamWriter, OutputStream}
import java.security.Key
import java.security.KeyPair
import java.security.PublicKey
import java.security.PrivateKey

import javax.security.cert.Certificate

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo
import org.bouncycastle.openssl.{PEMKeyPair, PEMParser, PEMWriter}
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter


trait Encoders extends StreamConversions {

  class PEMEncoder(objs: AnyRef*) extends Writeable {
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

  class PEMDecoder(in: InputStream) {

    val keypair =
      Option(new PEMParser(new InputStreamReader(in)).readObject) map {
        case priv: PrivateKeyInfo => new KeyPair(null, new JcaPEMKeyConverter().getPrivateKey(priv))
        case pub: SubjectPublicKeyInfo => new KeyPair(new JcaPEMKeyConverter().getPublicKey(pub), null)
        case pair: PEMKeyPair => new JcaPEMKeyConverter().getKeyPair(pair)
      } getOrElse (new KeyPair(null, null))

    def asPrivateKey: Option[PrivateKey] = Option(keypair.getPrivate)
    def asPublicKey: Option[PublicKey] = Option(keypair.getPublic)
  }

  object PEM {
    def encode(cert: Certificate): PEMCertificateEncoder = new PEMCertificateEncoder(cert)
    def encode(pair: KeyPair): PEMKeyPairEncoder = new PEMKeyPairEncoder(pair)
    def encode(key: PublicKey): PEMKeyEncoder = new PEMKeyEncoder(key)
    def encode(key: PrivateKey): PEMKeyEncoder = new PEMKeyEncoder(key)
    def decode(in: InputStream): PEMDecoder = new PEMDecoder(in)
  }
}
