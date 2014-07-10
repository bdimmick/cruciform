package com.hexagrammatic.cruciform

import org.scalatest.{Matchers, FlatSpec}

class EncodersSpec extends FlatSpec with Matchers with KeyGenerators with Encoders {

  "Encoders" should "be able to encode a private key as a a PEM without password" in {
    val keypair = RSA keypair
    val encoded = PEM encode keypair.getPrivate asBytes
    val decoded = PEM decode encoded


  }

}
