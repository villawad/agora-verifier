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

      try {
        val prefix = Array("vmnc", randomSource, "")
        val arguments = Array.concat(prefix, args.drop(1))
        println(s"* calling mixnet interface with ${arguments.mkString(" ")}..")
        MixNetElGamalInterface.main(arguments)
      } catch {
        case noexit: NEException => // munch System.exit
        case t: Throwable => throw t
      }

    } match {
      case Success(_) => println("* vmnc call succeeded")
      case Failure(e) => println("* verification FAILED"); e.printStackTrace()
    }
  }
}