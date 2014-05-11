package com.hexagrammatic.cruciform

import java.security.PrivateKey
import java.security.PublicKey
import java.security.KeyPair

class Keypair(pair: KeyPair) {
  def privateKey: PrivateKey = pair.getPrivate
  def publicKey: PublicKey = pair.getPublic
  def algorithm: String = pair.getPublic.getAlgorithm
}