package com.hexagrammatic.cruciform

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.FilterInputStream
import java.io.InputStream
import java.io.ObjectOutputStream
import java.io.OutputStream

import org.apache.commons.io.IOUtils.copy

/**
 * Trait to provide a stream during cryptographic operations
 */
trait Streamable {
  def toStream: InputStream
}

/**
 * A collection of utilities for creating and managing streams
 * during cryptographic operations.
 */
object StreamUtils {

  /**
   * Provides a funciton to read a stream fully, as a blocking operation, dropping all of the bytes read.
   */
  val NullStreamHandler = (i: InputStream) => {
    val buffer = new Array[Byte](128 * 1204)
    while (-1 != i.read(buffer)) {}
  }

  /**
   * Creates a function to read a stream fully, as a blocking operation,
   * writing the bytes out to the provided output stream.
   * @param o the destination output stream
   * @return the handling function
   */
  def copyHandler(o: OutputStream): (InputStream) => Unit = {
    (i: InputStream) => {
      copy(i, o)
    }
  }

  /**
   * Converts the provided object to a stream for use in cryptographic operations.
   * The conversion rules are as follows, in the following order:
   *   * `Streamable` objects have the result of their `toStream` method returned
   *   * `InputStream`s are returned as-is
   *   * `String`s return a stream of their bytes in the platform's default charset
   *   * `Array[Byte]`s return a stream of the provided array
   *   * `Array[Char]`s  return a stream of their bytes in the platform's default charset
   *   * `Serializable`s return a stream of bytes as written to an ObjectOutputStream
   * @param data the object to convert
   * @return the stream
   * @throws IllegalArgumentException if the object cannot be converted to a stream
   */
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

  /**
   * Converts a byte-handling function to a curryable function that can handle buffers of bytes.
   * @param f the individual byte-handling function
   * @param buf the buffer to be written in the curried function
   * @param off the offset of the buffer to be written in the curried function
   * @param len the length of the buffer to be written in the curried function
   * @return the curried function
   */
  def makeBufferedFilter(f:(Byte => Any))(buf: Array[Byte], off: Int, len: Int) =
    buf.slice(off, off + len).foreach(f)

  /**
   * Class to perform filtering operations on a stream as it is read
   * @param in the input stream to filter on
   * @param byteHandler handler for individual bytes
   * @param bufferHandler handler for byte buffers - defaults to a function built by `makeBufferedFilter`
   */
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
        bufferHandler.getOrElse(makeBufferedFilter(byteHandler) _)(b, off, result)
      }
      result
    }
  }
}