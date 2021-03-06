package com.hexagrammatic.cruciform

import java.io.{InputStreamReader, InputStream, OutputStreamWriter, OutputStream}
import java.security.KeyPair
import java.security.PublicKey
import java.security.PrivateKey

import javax.security.cert.Certificate

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo
import org.bouncycastle.openssl.{PEMEncryptedKeyPair, PEMKeyPair, PEMParser, PEMWriter}
import org.bouncycastle.openssl.jcajce.{JcePEMDecryptorProviderBuilder, JcePEMEncryptorBuilder, JcaPEMKeyConverter}


trait Codecs extends StreamConversions {

  class PEMEncoder(objs: AnyRef*) extends Writeable {
    def write(writer: PEMWriter, obj: AnyRef) {
      writer.writeObject(obj)
    }

    def to[T <: OutputStream](out: T): T = {
      val writer = new PEMWriter(new OutputStreamWriter(out))
      objs.foreach((r:AnyRef) => write(writer, r))
      writer.flush
      out
    }
  }

  class PEMCertificateEncoder(cert: Certificate) extends PEMEncoder(cert)

  class PEMPublicKeyEncoder(key: PublicKey) extends PEMEncoder(key)

  class PEMPrivateKeyEncoder(
      key: PrivateKey,
      password: Option[String] = None,
      encryptionAlgortihm: Option[String] = None) extends PEMEncoder(key) {

    val encryptorBuilder = encryptionAlgortihm match {
      case Some(algorithm) => new JcePEMEncryptorBuilder(algorithm)
      case None => new JcePEMEncryptorBuilder("AES-256-CBC")
    }

    def withPassword(password: String): PEMPrivateKeyEncoder =
      new PEMPrivateKeyEncoder(key, Option(password), encryptionAlgortihm)

    def withEncryptionAlgorithm(algorithm: String): PEMPrivateKeyEncoder =
      new PEMPrivateKeyEncoder(key, password, Option(algorithm))

    override def write(writer: PEMWriter, obj: AnyRef) {
      password match {
        case Some(password) => writer.writeObject(obj, encryptorBuilder.build(password.toCharArray))
        case None => writer.writeObject(obj)
      }
    }
  }

  class PEMDecoder(
      in: InputStream,
      password: Option[String] = None) {

    private[this] val EmptyKeyPair = new KeyPair(null, null)

    def keypair =
      Option(new PEMParser(new InputStreamReader(in)).readObject) map {
        case priv: PrivateKeyInfo => new KeyPair(null, new JcaPEMKeyConverter().getPrivateKey(priv))
        case pub: SubjectPublicKeyInfo => new KeyPair(new JcaPEMKeyConverter().getPublicKey(pub), null)
        case pair: PEMKeyPair => new JcaPEMKeyConverter().getKeyPair(pair)
        case encrypted: PEMEncryptedKeyPair => {
          password match {
            case Some(password) => {
              val decryptor = new JcePEMDecryptorProviderBuilder().build(password.toCharArray)
              new JcaPEMKeyConverter().getKeyPair(encrypted.decryptKeyPair(decryptor))
            }
            case None => EmptyKeyPair
          }
        }
      } getOrElse (EmptyKeyPair)

    def withPassword(password: String): PEMDecoder = new PEMDecoder(in, Option(password))

    def asPrivateKey: Option[PrivateKey] = Option(keypair.getPrivate)
    def asPublicKey: Option[PublicKey] = Option(keypair.getPublic)
  }

  object PEM {
    def encode(cert: Certificate): PEMCertificateEncoder = new PEMCertificateEncoder(cert)
    def encode(key: PublicKey): PEMPublicKeyEncoder = new PEMPublicKeyEncoder(key)
    def encode(key: PrivateKey): PEMPrivateKeyEncoder = new PEMPrivateKeyEncoder(key)
    def decode(in: InputStream): PEMDecoder = new PEMDecoder(in)
  }
}
