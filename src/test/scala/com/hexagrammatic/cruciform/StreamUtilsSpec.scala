package com.hexagrammatic.cruciform

import StreamUtils._

import java.io._

import org.apache.commons.io.input.CountingInputStream
import org.scalatest.FlatSpec
import org.scalatest.Matchers

class StreamUtilsSpec extends FlatSpec with Matchers {

  def randomInt = scala.util.Random.nextInt

  "Stream utils" should "be able to provide a no-op handler that reads an entire stream" in {
    val data = "Hello World"
    val stream = new CountingInputStream(new ByteArrayInputStream(data.getBytes))
    
    noopHandler(stream)
    
    (stream.getByteCount) should equal (data.getBytes.length)
  }

  "Stream utils" should "be able to provide a handler that copies an entire stream" in {
    val data = "Hello World"
    val in = new ByteArrayInputStream(data.getBytes)
    val out = new ByteArrayOutputStream
    
    copyHandler(out)(in)
    
    (out.toByteArray.deep) should equal (data.getBytes.deep)
  }

  "Stream utils" should "be able to convert a string to a stream" in {
    val data = "Hello World"
    val in = toStream(data)
    val out = new ByteArrayOutputStream
    
    copyHandler(out)(in)
    
    (out.toByteArray.deep) should equal (data.getBytes.deep)
  }

  "Stream utils" should "be able to convert a byte array to a stream" in {
    val data = "Hello World"
    val in = toStream(data.getBytes)    
    val out = new ByteArrayOutputStream
    
    copyHandler(out)(in)
    
    (out.toByteArray.deep) should equal (data.getBytes.deep)
  }

  "Stream utils" should "'convert' a stream to a stream" in {
    val data = "Hello World"
    val in = toStream(new ByteArrayInputStream(data.getBytes))    
    val out = new ByteArrayOutputStream
    
    copyHandler(out)(in)
    
    (out.toByteArray.deep) should equal (data.getBytes.deep)
  }

  "Stream utils" should "be able to convert a char array to a stream" in {
    val data = "Hello World"
    val in = toStream(data.toCharArray)    
    val out = new ByteArrayOutputStream
    
    copyHandler(out)(in)
    
    (out.toByteArray.deep) should equal (data.getBytes.deep)
  }

  private class TestingStreamable(s:String) extends Streamable {
    override def toStream:InputStream = new ByteArrayInputStream(s.getBytes)
  }
 
  "Stream utils" should "be able to convert a streamable to a stream" in {
    val data = "Hello World"
    val in = toStream(new TestingStreamable(data))    
    val out = new ByteArrayOutputStream
    
    copyHandler(out)(in)
    
    (out.toByteArray.deep) should equal (data.getBytes.deep)
  }

  "Stream utils" should "be able to convert a serializable to a stream" in {
    val serialized = new TestSerializable(randomInt)
    val in = toStream(serialized)
    val out = new ByteArrayOutputStream

    copyHandler(out)(in)

    val oin = new ObjectInputStream(new ByteArrayInputStream(out.toByteArray))
    val o = oin.readObject

    o match {
      case s: TestSerializable => (s) should equal (serialized)
    }
  }
}

// Used to test serialization abilities of toStream -
// required to be outside the test class so there's
// no implicit reference to the test class in serialization
case class TestSerializable(t:Int) extends Serializable {
}

