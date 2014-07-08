package com.hexagrammatic.cruciform

import java.security.Provider
import java.security.Security

import org.bouncycastle.jce.provider.BouncyCastleProvider
import scala.collection.JavaConversions

/**
 * Core class to provide common functionality
 */
trait Core {
  type OptionalProvider = Either[String, Provider]
  protected val BouncyCastle = toOptionalProvider(new BouncyCastleProvider())
  protected val DefaultProvider = BouncyCastle

  Security.addProvider(DefaultProvider.right.get)

  implicit def toOptionalProvider(s: String): OptionalProvider = Left(s)
  implicit def toOptionalProvider(p: Provider): OptionalProvider = Right(p)

  def fromProvider[T](provider: OptionalProvider, fromRight: (Provider => T), fromLeft: (String => T)): T =
    provider match {
      case Right(provider) => fromRight(provider)
      case Left(string) => fromLeft(string)
    }
}
