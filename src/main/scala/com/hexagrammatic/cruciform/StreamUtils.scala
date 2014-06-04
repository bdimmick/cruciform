package com.hexagrammatic.cruciform

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.FilterInputStream
import java.io.InputStream
import java.io.ObjectOutputStream
import java.io.OutputStream

import org.apache.commons.io.IOUtils.copy

trait Streamable {
  def toStream: InputStream
}

object StreamUtils {
  val noopHandler = (i: InputStream) => {
    val buffer = new Array[Byte](128 * 1204)
    while (-1 != i.read(buffer)) {}
  }

  def copyHandler(o: OutputStream): (InputStream) => Unit = {
    (i: InputStream) => {
      copy(i, o)
    }
  }

  def toStream(data: Any): InputStream = {
    data match {
      case x: Streamable => x.toStream
      case i: InputStream => i
      case s: String => new ByteArrayInputStream(s.getBytes)
      case a: Array[Byte] => new ByteArrayInputStream(a)
      case a: Array[Char] => new ByteArrayInputStream(new String(a).getBytes)
      case s: Serializable => {
        val bstream = new ByteArrayOutputStream
        val ostream = new ObjectOutputStream(bstream)
        ostream.writeObject(s)
        ostream.flush
        new ByteArrayInputStream(bstream.toByteArray)
      }
      /* TODO(me@billdimmick.com): Add Thrift Support? */
      case _ => {
        val message = String.format("Cannot create stream for object of type %s", data.getClass)
        throw new IllegalArgumentException(message)
      }
    }
  }

  def makeBufferHandler(f:(Byte => Any))(buf: Array[Byte], off: Int, len: Int) =
    buf.slice(off, off + len).foreach(f)

  class FunctionFilterStream(
    in: InputStream,
    byteHandler: (Byte) => Any,
    bufferHandler: Option[(Array[Byte], Int, Int) => Any] = None)
    extends FilterInputStream(in) {

    override def read: Int = {
      val ch = in.read()
      if (ch != -1) {
        byteHandler(ch.byteValue)
      }
      ch
    }

    override def read(b: Array[Byte], off: Int, len: Int): Int = {
      val result = in.read(b, off, len)
      if (result > 0) {
        bufferHandler.getOrElse(makeBufferHandler(byteHandler) _)(b, off, result)
      }
      result
    }
  }
}