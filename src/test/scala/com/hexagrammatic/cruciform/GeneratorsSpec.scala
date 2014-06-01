package com.hexagrammatic.cruciform

import Generators._

import org.scalatest.FlatSpec
import org.scalatest.Matchers

import java.security.InvalidParameterException
import java.security.NoSuchAlgorithmException


class GeneratorsSpec extends FlatSpec with Matchers {

  "Key generator" should "be able to generate a key with no params" in {
    val generator = new SymmetricKeyGenerator()
    val key = generator.generate
    
    key should not be null    
    key should not equal (generator.generate)
  }

  "Key generator" should "be able to generate a key with algorithm and strength" in {
    val str = 56
    val alg = "DES"
    val generator = new SymmetricKeyGenerator(alg, strength = Option(str))
    val key = generator.generate
        
    key should not be null
    key.getAlgorithm should equal (alg)
    key should not equal (generator.generate)
  }

  "Key generator" should "be able to generate a key with just strength" in {
    val str = 128
    val generator = new SymmetricKeyGenerator(strength = Option(str))
    val key = generator.generate
    
    key should not be null
    key should not equal (generator.generate)
    key.getEncoded.length should equal (str / 8)
  }

  "Key generator function" should "be able to generate a key with no params" in {
    key should not be null
  }

  "Key generator function" should "be able to generate a key with algorithm and strength" in {
    val str = 56
    val alg = "DES"
    val k = Generators.key(alg, strength = Option(str))
    
    k.getAlgorithm should equal (alg)
  }

  "Key generator function" should "be able to generate a key with just strength" in {
    val str = 128
    val k = Generators.key(strength = Option(str))
    
    k.getEncoded.length should equal (str / 8)
  }

  "Key generator function" should "fail with invalid strength" in {
    an [InvalidParameterException] should be thrownBy Generators.key(strength = Option(17))
  }

  "Key generator function" should "fail with invalid algorithm" in {    
    an [NoSuchAlgorithmException] should be thrownBy Generators.key(algorithm = "BAD")
  }
  
  "Keypair generator" should "be able to generate a keypair with no params" in {
    val generator = new AsymmetricKeyGenerator()
    val pair = generator.generate
    
    pair should not be null
    pair.privateKey should not be null
    pair.publicKey should not be null
  }

  "Keypair generator" should "be able to generate a keypair with just strength" in {
    val generator = new AsymmetricKeyGenerator(strength = Option(1024))
    val pair = generator.generate
    
    pair should not be null
    pair.privateKey should not be null
    pair.publicKey should not be null
  }

  "Keypair generator" should "be able to generate a keypair with algorithm" in {
    val alg = "DSA"
    val generator = new AsymmetricKeyGenerator(alg)
    val pair = generator.generate
    
    pair should not be null
    pair.privateKey should not be null
    pair.publicKey should not be null    
    pair.algorithm should equal (alg)
  }
  
  "Keypair generator function" should "be able to generate a keypair with no params" in {
    val pair = keypair()
    
    pair should not be null
    pair.privateKey should not be null
    pair.publicKey should not be null    
  }

  "Keypair generator function" should "be able to generate a keypair with just strength" in {
    val pair = keypair(strength = Option(1024))
    
    pair should not be null
    pair.privateKey should not be null
    pair.publicKey should not be null    
  }

  "Keypair generator function" should "be able to generate a keypair with algorithm" in {
    val alg = "DSA"
    val pair = keypair(alg)
    
    pair should not be null
    pair.privateKey should not be null
    pair.publicKey should not be null    
    pair.algorithm should equal (alg)  }
}