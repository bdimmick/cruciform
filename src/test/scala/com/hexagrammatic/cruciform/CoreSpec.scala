package com.hexagrammatic.cruciform

import java.security.Provider

import org.scalatest.{Matchers, FlatSpec}
import org.scalamock.scalatest.MockFactory

class CoreSpec extends FlatSpec with Matchers with MockFactory with Core {

  object MockProvider extends Provider("Mock", 0.0, "Mock")

  "Core" should "operate on the Provider if provided" in {
    assert(
      fromProvider[Boolean](
        MockProvider,
        (p: Provider) => true,
        (s: String) =>  false
      )
    )
  }

  "Core" should "operate on the String if provided" in {
    assert(
      fromProvider[Boolean](
        "BC",
        (p: Provider) => false,
        (s: String) =>  true
      )
    )
  }
}
