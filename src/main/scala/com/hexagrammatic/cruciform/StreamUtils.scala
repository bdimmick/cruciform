package com.hexagrammatic.cruciform

import java.io._

import org.apache.commons.io.IOUtils.copy
import scala.Serializable


/**
 * Trait to provide a stream during cryptographic operations
 */
trait Readable {
  def stream: InputStream
}

trait Writeable {
  def to[T <: OutputStream](out: T): T
  def toBytes: Array[Byte] = to(new ByteArrayOutputStream).toByteArray
  override def toString: String = new String(toBytes)
}

/**
 * Provides functionality to convert the provided object to a stream for use in cryptographic operations.
 * The input conversion rules are as follows, in the following order:
 *   * `Streamable` objects have the result of their `toStream` method returned
 *   * `InputStream`s are returned as-is
 *   * `File`s are opened as a FileInputStream.
 *   * `String`s return a stream of their bytes in the platform's default charset
 *   * `Array[Byte]`s return a stream of the provided array
 *   * `Array[Char]`s  return a stream of their bytes in the platform's default charset
 *   * `Serializable`s return a stream of bytes as written to an ObjectOutputStream
 */
trait StreamConversions {
  implicit def toOutputStream(f: File): OutputStream = new FileOutputStream(f)
  implicit def toInputStream(s: String): InputStream = new ByteArrayInputStream(s.getBytes)
  implicit def toInputStream(x: Readable): InputStream = x.stream
  implicit def toInputStream(a: Array[Byte]): InputStream = new ByteArrayInputStream(a)
  implicit def toInputStream(a: Array[Char]): InputStream = new ByteArrayInputStream(new String(a).getBytes)
  implicit def toInputStream(f: File): InputStream = new FileInputStream(f)
  implicit def toInputStream(s: Serializable): InputStream = {
    val bstream = new ByteArrayOutputStream
    val ostream = new ObjectOutputStream(bstream)
    ostream.writeObject(s)
    ostream.flush
    new ByteArrayInputStream(bstream.toByteArray)
  }
  /* TODO(me@billdimmick.com): Add Thrift Support? */
}

/**
 * A collection of utilities for creating and managing streams
 * during cryptographic operations.
 */
object StreamUtils {

  type StreamHandler = (InputStream) => Unit

  /**
   * Provides a function to read a stream fully, as a blocking operation,
   * dropping all of the bytes read.
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
  def copyHandler(o: OutputStream): StreamHandler = {
    (i: InputStream) => {
      copy(i, o)
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