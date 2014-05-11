package com.hexagrammatic.cruciform

import java.io.InputStream
import java.io.ByteArrayInputStream
import java.io.Reader
import java.io.OutputStream

import org.apache.commons.io.IOUtils


trait Streamable {
  def toStream: InputStream
}

object StreamUtils {
  val noopHandler = (i: InputStream) => {
    val buffer = new Array[Byte](128 * 1204)
    while (-1 != i.read(buffer)) {}
  }
  
  def copyHandler(o: OutputStream): (InputStream) => Unit = {
    (i: InputStream) =>
      {
        IOUtils.copy(i, o)
      }
  }

  def toStream(data: Any): InputStream = {
    data match {
      case x: Streamable => x.toStream
      case i: InputStream => i
      case s: String => new ByteArrayInputStream(s.getBytes)
      case a: Array[Byte] => new ByteArrayInputStream(a)
      case a: Array[Char] => new ByteArrayInputStream(new String(a).getBytes)
/*      
      case a: Array[Double] => new ByteArrayInputStream(a.map((d: Double) => d.toByte).toArray)
      case a: Array[Float] => new ByteArrayInputStream(a.map((f: Float) => f.toByte).toArray)
      case a: Array[Int] => new ByteArrayInputStream(a.map((i: Int) => i.toByte).toArray)
      case a: Array[Long] => new ByteArrayInputStream(a.map((l: Long) => l.toByte).toArray)
      case a: Array[Short] => new ByteArrayInputStream(a.map((s: Short) => s.toByte).toArray)
*/
      case _ => {
        val message = String.format("Cannot create stream for object of type %s", data.getClass)
        throw new IllegalArgumentException(message)
      }
    }
  }

}