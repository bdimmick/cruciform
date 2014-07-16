/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

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
import javax.crypto.SecretKey
import javax.crypto.spec.IvParameterSpec


trait Ciphers extends Core with StreamConversions {

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

  private def createCipher(algorithm: Option[String], key: Key, provider: OptionalProvider): Cipher = {
    val foundAlgorithm = algorithm getOrElse algorithmForKey(key, CipherForKeyType)

    fromProvider[Cipher](
      provider,
      (p: Provider) => Cipher getInstance(foundAlgorithm, p),
      (s: String) => Cipher getInstance(foundAlgorithm, s)
    )
  }

  private def createSignature(algorithm: Option[String], key: Key, provider: OptionalProvider): Signature = {
    val foundAlgorithm = algorithm getOrElse algorithmForKey(key, SignatureForKeyType)

    fromProvider[Signature](
      provider,
      (p: Provider) => Signature getInstance(foundAlgorithm, p),
      (s: String) => Signature getInstance(foundAlgorithm, s)
    )
  }

  private def makeSigningFilterStream(data: InputStream, signer: Signature): FunctionFilterStream = {
    new FunctionFilterStream(
      data,
      (b: Byte) => signer.update(b),
      Option((a: Array[Byte], off: Int, len: Int) => signer.update(a, off, len))
    )
  }

  class AsymmetricEncryptOperation(
      data: InputStream,
      key: Key,
      algorithm: Option[String] = None,
      provider: OptionalProvider = DefaultProvider) extends Writeable {

    def to[T <: OutputStream](out: T): T = {
      val cipher = createCipher(algorithm, key, provider)
      cipher init(ENCRYPT_MODE, key)
      copyHandler(out)(new CipherInputStream(data, cipher))
      out
    }

    /**
     * Sets the algorithm to use with this asymmetric encryption.
     */
    def withAlgorithm(algorithm: String): AsymmetricEncryptOperation =
      new AsymmetricEncryptOperation(data, key, Option(algorithm), provider)

    /**
     * Sets the JCE provider to use with this asymmetric encryption.
     */
    def withProvider(provider: OptionalProvider): AsymmetricEncryptOperation =
      new AsymmetricEncryptOperation(data, key, algorithm, provider)
  }

  class SymmetricEncryptOperation(
      data: InputStream,
      key: Key,
      algorithm: Option[String] = None,
      provider: OptionalProvider = DefaultProvider) {

    def to[T <: OutputStream](out: T): (T, Option[Array[Byte]]) = {
      val cipher = createCipher(algorithm, key, provider)
      cipher init(ENCRYPT_MODE, key)
      copyHandler(out)(new CipherInputStream(data, cipher))
      (out, Option(cipher.getIV))
    }

    def asBytes:(Array[Byte], Option[Array[Byte]]) = {
      val (out, iv) = to(new ByteArrayOutputStream)
      (out.toByteArray, iv)
    }

    def asString:(String, Option[Array[Byte]]) = {
      val (bytes, iv) = asBytes
      (new String(bytes), iv)
    }

    /**
     * Sets the algorithm to use with this symmetric encryption.
     */
    def withAlgorithm(algorithm: String): SymmetricEncryptOperation =
      new SymmetricEncryptOperation(data, key, Option(algorithm), provider)

    /**
     * Sets the JCE provider to use with this symmetric encryption.
     */
    def withProvider(provider: OptionalProvider): SymmetricEncryptOperation =
      new SymmetricEncryptOperation(data, key, algorithm, provider)
  }

  class EncryptAskForKey(data: InputStream) {
    /**
     * Sets the certificate to use when performing this encryption operation and sets the operation
     * into asymmetric mode.  Follow this statement with asymmetric encryption options.
     */
    def using(cert: Certificate): AsymmetricEncryptOperation = this using (cert.getPublicKey)

    /**
     * Sets the public to use when performing this encryption operation and sets the operation
     * into asymmetric mode.  Follow this statement with asymmetric encryption options.
     */
    def using(key: PublicKey): AsymmetricEncryptOperation = new AsymmetricEncryptOperation(data, key)

    /**
     * Sets the symmetric key to use when performing this encryption operation and sets the operation
     * into symmetric mode.  Follow this statement with symmetric encryption options.
     */
    def using(key: SecretKey): SymmetricEncryptOperation = new SymmetricEncryptOperation(data, key)

    /**
     * Sets the public key to use when performing this encryption operation from the provided keypair
     * and sets the into asymmetric mode.  Follow this statement with asymmetric encryption options.
     */
    def using(pair: KeyPair): AsymmetricEncryptOperation = this using (pair.getPublic)
  }

  class AsymmetricEncryptAskForData(key: PublicKey) {
    /**
     * Sets the data to encrypt.  Follow this statement with asymmetric encryption options.
     */
    def data(data: InputStream): AsymmetricEncryptOperation = new AsymmetricEncryptOperation(data, key)
  }

  class SymmetricEncryptAskForData(key: SecretKey) {
    /**
     * Sets the data to encrypt.  Follow this statement with symmetric encryption options.
     */
    def data(data: InputStream): SymmetricEncryptOperation = new SymmetricEncryptOperation(data, key)
  }

  class EncryptAskForDataOrKey {
    /**
     * Sets the data to encrypt.  Follow this statement with `using <key>`.
     */
    def data(data: InputStream): EncryptAskForKey = new EncryptAskForKey(data)

    /**
     * Sets the certificate to use when performing this encryption operation and sets the operation
     * into asymmetric mode.  Follow this statement with `data <stream>`.
     */
    def using(cert: Certificate):  AsymmetricEncryptAskForData = this using (cert.getPublicKey)

    /**
     * Sets the symmetric key to use when performing this encryption operation and sets the operation
     * into symmetric mode.  Follow this statement with `data <stream>`.
     */
    def using(key: SecretKey):  SymmetricEncryptAskForData = new  SymmetricEncryptAskForData(key)

    /**
     * Sets the public key to use when performing this encryption operation and sets the operation
     * into asymmetric mode.  Follow this statement with `data <stream>`.
     */
    def using(key: PublicKey):  AsymmetricEncryptAskForData = new  AsymmetricEncryptAskForData(key)

    /**
     * Sets the public key to use when performing this encryption operation from the provided keypair
     * and sets the operation into asymmetric mode.  Follow this statement with `data <stream>`.
     */
    def using(pair: KeyPair):  AsymmetricEncryptAskForData = this using (pair.getPublic)
  }

  /**
   * Starts an encryption operation.  Follow this statement with `data <steam>` or `using <key>`.
   */
  def encrypt: EncryptAskForDataOrKey = new EncryptAskForDataOrKey

  class DecryptOperation(
      data: InputStream,
      key: Key,
      initVector: Option[Array[Byte]] = None,
      algorithm: Option[String] = None,
      provider: OptionalProvider = DefaultProvider) extends Writeable {

    /**
     * Performs the decryption and writes the plaintext out to the provided stream.
     * Use `asBytes` or `asString` to return the plaintext as an Array[Byte] or Stirng, repsectively.
     */
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

    /**
     * Sets the algorithm to use in this decryption.
     */
    def withAlgorithm(algorithm: String): DecryptOperation =
      new DecryptOperation(data, key, initVector, Option(algorithm), provider)

    /**
     * Sets the init vector to use in this decryption.
     */
    def withInitVector(iv: Array[Byte]): DecryptOperation =
      new DecryptOperation(data, key, Option(iv), algorithm, provider)

    /**
     * Sets the JCE provider to use in this decryption.
     */
    def withProvider(provider: OptionalProvider): DecryptOperation =
      new DecryptOperation(data, key, initVector, algorithm, provider)
  }

  class DecryptAskForKey(data: InputStream) {
    /**
     * Sets the key to use in this decryption.  Follow this statement with decrypt options.
     */
    def using(key: Key): DecryptOperation = new DecryptOperation(data, key)

    /**
     * Sets the key from a keypair to use in this decryption.  Follow this statement with decrypt options.
     */
    def using(pair: KeyPair): DecryptOperation = this using pair.getPrivate
  }

  /**
   * Sets the data to sign.  Follow this statement with decrypt options.
   */
  class DecryptAskForData(key: Key) {
    def data(data: InputStream): DecryptOperation = new DecryptOperation(data, key)
  }

  class DecryptAskForDataOrKey {
    /**
     * Sets the data to sign.  Follow this statement with `using <key>`.
     */
    def data(data: InputStream): DecryptAskForKey = new DecryptAskForKey(data)

    /**
     * Sets the key to use in this decryption.  Follow this statement with `data <stream>`.
     */
    def using(key: Key): DecryptAskForData = new DecryptAskForData(key)

    /**
     * Sets the key from a keypair to use in this decryption.  Follow this statement with `data <stream>`.
     */
    def using(pair: KeyPair): DecryptAskForData = this using pair.getPrivate
  }


  /**
   * Starts a decryption operation.  Follow this statement with `data <steam>` or `using <key>`.
   */
  def decrypt: DecryptAskForDataOrKey = new DecryptAskForDataOrKey

  class SignOperation(
       data: InputStream,
       key: PrivateKey,
       algorithm: Option[String] = None,
       provider: OptionalProvider = DefaultProvider) extends Writeable {

    /**
     * Completes the signing operation and writes out the signature bytes to the provided stream.
     * Use `asBytes` or `asString` to return the plaintext as an Array[Byte] or Stirng, repsectively.
     */
    def to[T <: OutputStream](out: T): T = {
      val signer = createSignature(algorithm, key, provider)
      signer initSign(key)
      NullStreamHandler(makeSigningFilterStream(data, signer))

      out write(signer.sign)
      out
    }

    /**
     * Sets the algorithm to use with this signing operation.
     */
    def withAlgorithm(algorithm: String): SignOperation =
      new SignOperation(data, key, Option(algorithm), provider)

    /**
     * Sets the JCE provider to use with this JCE operation.
     */
    def withProvider(provider: OptionalProvider): SignOperation =
      new SignOperation(data, key, algorithm, provider)
  }

  class SignAskForKey(data: InputStream) {
    /**
     * Sets the private key to use when generating the signature.  Follow this statement with signing options.
     */
    def using(key: PrivateKey): SignOperation = new SignOperation(data, key)

    /**
     * Sets the private key froim a keypair to use when generating the signature.
     * Follow this statement with signing options.
     */
    def using(pair: KeyPair): SignOperation = this using pair.getPrivate
  }

  class SignAskForData(key: PrivateKey) {
    /**
     * Sets the data to sign.  Follow this statement with signing options.
     *
     *@param data the data, as an `InputStream` - implicits provide convenience conversions.
     **/
    def data(data: InputStream): SignOperation = new SignOperation(data, key)
  }

  class SignAskForDataOrKey {
    /**
     * Sets the data to sign.  Follow this statement with `using <key>`.
     *
     * @param data the data, as an `InputStream` - implicits provide convenience conversions.
     **/
    def data(data: InputStream): SignAskForKey = new SignAskForKey(data)

    /**
     * Sets the private key to use when generating the signature.  Follow this statement with `data <stream>`.
     */
    def using(key: PrivateKey): SignAskForData = new SignAskForData(key)

    /**
     * Sets the private key froim a keypair to use when generating the signature.
     * Follow this statement with `data <stream>`.
     */
    def using(pair: KeyPair): SignAskForData = this using pair.getPrivate
  }

  /**
   * Starts a signing operation, writing out the signature to another stream.
   *
   * Follow this statement with either `using <key>` or `data <stream>`.
   *
   */
  def sign: SignAskForDataOrKey = new SignAskForDataOrKey

  class VerifyOperation(
    signature: InputStream,
    key: PublicKey,
    algorithm: Option[String] = None,
    provider: OptionalProvider = DefaultProvider) {

    /**
     * Sets the `InputStream` that contains the data to use in signature verification and then performs the
     * verification, returning `true` if the verification succeeds.
     * @param data the data, as an `InputStream` - implicits provide convenience conversions.
     */
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

    /**
     * Sets the algorithm to use when verifying this signature.
     */
    def withAlgorithm(algorithm: String): VerifyOperation =
      new VerifyOperation(signature, key, Option(algorithm), provider)

    /**
     * Sets the JCE provider to use when verifying this signature.
     */
    def withProvider(provider: OptionalProvider): VerifyOperation =
      new VerifyOperation(signature, key, algorithm, provider)

  }

  class VerifyAskForKey(signature: InputStream) {
    /**
     * Adds the certificate to use in verification.  Follow this statement with signature options.
     */
    def using(cert: Certificate): VerifyOperation = this using cert.getPublicKey

    /**
     * Adds the public key to use in verification.  Follow this statement with signature options.
     */
    def using(key: PublicKey): VerifyOperation = new VerifyOperation(signature, key)

    /**
     * Adds public key from a keypair to use in verification.  Follow this statement with signature options.
     */
    def using(pair: KeyPair): VerifyOperation = this using pair.getPublic
  }

  class VerifyAskForSignature(key: PublicKey) {
    /**
     * Adds the signature to verify.  Follow this statement with signature options.
     * @param signature the signature, as an `InputStream` - implicits provide conversions.
     */
    def signature(signature: InputStream): VerifyOperation = new VerifyOperation(signature, key)
  }

  class VerifyAskForSignatureOrKey {
    /**
     * Adds the signature to verify.  Follow this statement with `using <key>`
     * @param signature the signature, as an `InputStream` - implicits provide convenience conversions.
     */
    def signature(signature: InputStream): VerifyAskForKey = new VerifyAskForKey(signature)

    /**
     * Adds the certificate to use in verification.  Follow this statement with `signature <stream>`.
     */
    def using(cert: Certificate): VerifyAskForSignature = this using cert.getPublicKey

    /**
     * Adds the public key to use in verification.  Follow this statement with `signature <stream>`.
     */
    def using(key: PublicKey): VerifyAskForSignature = new VerifyAskForSignature(key)

    /**
     * Adds the public key from a keypair to use in verification.  Follow this statement with `signature <stream>`.
     */
    def using(pair: KeyPair): VerifyAskForSignature = this using pair.getPublic
  }

  /**
   * Starts a verification operation, returning `true` if the verification is
   * successful, `false` otherwise.
   *
   * Follow this statement with either `using <key>` or `signature <stream>`.
   *
   */
  def verify: VerifyAskForSignatureOrKey = new VerifyAskForSignatureOrKey
}