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

import StreamUtils._

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.io.ObjectInputStream
import java.util.concurrent.atomic.AtomicInteger

import org.apache.commons.io.input.CountingInputStream
import org.scalatest.FlatSpec
import org.scalatest.Matchers


class StreamUtilsSpec extends FlatSpec with Matchers with StreamConversions {

  def randomInt = scala.util.Random.nextInt

  val data = "Hello World"

  "Stream utils" should "be able to provide a no-op handler that reads an entire stream" in {
    val stream = new CountingInputStream(new ByteArrayInputStream(data.getBytes))

    NullStreamHandler(stream)
    
    (stream.getByteCount) should equal (data.getBytes.length)
  }

  "Stream utils" should "be able to provide a handler that copies an entire stream" in {
    val in = new ByteArrayInputStream(data.getBytes)
    val out = new ByteArrayOutputStream
    
    copyHandler(out)(in)
    
    (out.toByteArray.deep) should equal (data.getBytes.deep)
  }

  "Stream utils" should "be able to convert a string to a stream" in {
    val in = toInputStream(data)
    val out = new ByteArrayOutputStream
    
    copyHandler(out)(in)
    
    (out.toByteArray.deep) should equal (data.getBytes.deep)
  }

  "Stream utils" should "be able to convert a byte array to a stream" in {
    val in = toInputStream(data.getBytes)
    val out = new ByteArrayOutputStream
    
    copyHandler(out)(in)
    
    (out.toByteArray.deep) should equal (data.getBytes.deep)
  }

  "Stream utils" should "be able to convert a char array to a stream" in {
    val data = "Hello World"
    val in = toInputStream(data.toCharArray)
    val out = new ByteArrayOutputStream
    
    copyHandler(out)(in)
    
    (out.toByteArray.deep) should equal (data.getBytes.deep)
  }

  private class TestingReadable(s:String) extends Readable {
    override def stream:InputStream = new ByteArrayInputStream(s.getBytes)
  }
 
  "Stream utils" should "be able to convert a streamable to a stream" in {
    val in = toInputStream(new TestingReadable(data))
    val out = new ByteArrayOutputStream
    
    copyHandler(out)(in)
    
    (out.toByteArray.deep) should equal (data.getBytes.deep)
  }

  "Stream utils" should "be able to convert a serializable to a stream" in {
    val serialized = new TestSerializable(randomInt)
    val in = toInputStream(serialized)
    val out = new ByteArrayOutputStream

    copyHandler(out)(in)

    val oin = new ObjectInputStream(new ByteArrayInputStream(out.toByteArray))
    val o = oin.readObject

    o match {
      case s: TestSerializable => (s) should equal (serialized)
    }
  }

  "Stream utils" should "be able to provide a default buffer handler for a functional stream" in {
    val count = new AtomicInteger(0)
    val f = (b: Byte) => count.incrementAndGet
    val out = new ByteArrayOutputStream

    copyHandler(out)(new FunctionFilterStream(toInputStream(data), f))

    (count.get) should equal (data.length)
  }

  "Stream utils" should "be able to utilize a buffer handler for a functional stream" in {
    val byteUseCount = new AtomicInteger(0)
    val bufferUseCount = new AtomicInteger(0)
    val byteFunc = (b: Byte) => byteUseCount.incrementAndGet
    val bufferFunc = (buf: Array[Byte], off: Int, len: Int) => bufferUseCount.incrementAndGet

    val out = new ByteArrayOutputStream

    copyHandler(out)(new FunctionFilterStream(toInputStream(data), byteFunc, Option(bufferFunc)))

    (byteUseCount.get) should equal (0)
    (bufferUseCount.get) should be > (0)
  }

}

// Used to test serialization abilities of toStream -
// required to be outside the test class so there's
// no implicit reference to the test class in serialization
case class TestSerializable(t:Int) extends Serializable {
}

