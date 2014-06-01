package com.hexagrammatic.cruciform

import java.security.PrivateKey
import java.security.PublicKey
import java.security.KeyPair

case class Keypair(val pair: KeyPair) extends Serializable {
  def privateKey: PrivateKey = pair.getPrivate
  def publicKey: PublicKey = pair.getPublic
  def algorithm: String = pair.getPublic.getAlgorithm
}