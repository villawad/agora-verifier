package org.agoravoting.agora

import scala.util.{Try, Success, Failure}
import java.io.{File, ByteArrayOutputStream, PrintStream}
import verificatum.ui.gen.GeneratorTool
import verificatum.protocol.mixnet.MixNetElGamalInterface

object Vmnc extends App {

  vmnc(args)

  def vmnc(args: Array[String]) = {
    Try {
      System.setSecurityManager(new NESecurityManager())
      val randomSource = args(0)
      Verifier.ensureRandomSource(randomSource)

      // tap output
      val baos = new java.io.ByteArrayOutputStream();
//       System.setOut(new OutTap(baos))

      try {
        val prefix = Array("vmnc", randomSource, "")
        val arguments = Array.concat(prefix, args.drop(1))
        println(s"* calling mixnet interface with ${arguments.mkString(" ")}..")
        MixNetElGamalInterface.main(arguments)
      } catch {
        case noexit: NEException => // munch System.exit
        case t: Throwable => throw t
      }

      /* if(!baos.toString.contains("Verification completed SUCCESSFULLY")) {
        throw new Exception(s"proofs verification failed on path $directory")
      }*/

    } match {
      case Success(_) => println("* vmnc call succeeded")
      case Failure(e) => println("* verification FAILED"); e.printStackTrace()
    }
  }
}

// to tap System.out
/* class OutTap(val baos: ByteArrayOutputStream) extends PrintStream(baos) {
  override def println(s: String) = {
    super.println(s)
    Console.println
  }
  override def print(s: String) = {
    super.print(s)
    Console.print(s"* $s")
  }
}

// to trap System.exit
import java.security.Permission;
class NESecurityManager extends SecurityManager {
    override def checkPermission(perm: Permission) = {}
    override def checkPermission(perm: Permission, context: Object) = {}
    override def checkExit(status: Int) { throw new NEException }
}
class NEException extends RuntimeException
*/