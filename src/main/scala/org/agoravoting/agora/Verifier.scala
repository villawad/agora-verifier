package org.agoravoting.agora

import scala.util.{Try, Success, Failure}
import java.io.{File, ByteArrayOutputStream, PrintStream}
import verificatum.ui.gen.GeneratorTool
import verificatum.protocol.mixnet.MixNetElGamalVerifyRO

object Verifier extends App {
  
  if(args.length != 2) {
    println("verifier <random source> <tally directory>")
  } else if(new File(args(1)).exists) {    
    verify(args(0), args(1))
  }

  def verify(randomSource: String, proofs: String) = {
    Try {    
      System.setSecurityManager(new NESecurityManager())
      ensureRandomSource(randomSource)                     
      println(s"* begin proof verification on '$proofs'")
      
      new File(proofs).listFiles.filter(_.isDirectory).foreach { directory =>
        
        println(s"* processing $directory..")
        
        val protInfo = directory + File.separator + "protInfo.xml"
        val proofs = directory + File.separator + "proofs"
        val plainText = directory + File.separator + "plaintexts_json"                   

        // tap output
        val baos = new java.io.ByteArrayOutputStream();
        System.setOut(new OutTap(baos))

        try {
          MixNetElGamalVerifyRO.main(Array("vmnv", randomSource, "", protInfo, proofs, "-v"))
        } catch {            
          case noexit: NEException => // munch System.exit
          case t: Throwable => throw t
        }
        
        if(!baos.toString.contains("Verification completed SUCCESSFULLY")) {
          throw new Exception(s"proofs verification failed on path $directory")
        }                    
//        val plainLines = io.Source.fromFile(plainText).getLines.toList
//        val options = plainLines.groupBy(x => x).mapValues(_.size)
//        println(s"> totals $options")
      }      
    } match {
      case Success(_) => println("* verification is OK")
      case Failure(e) => println("* verification FAILED"); e.printStackTrace()
    }
  }
  
  def ensureRandomSource(source: String) = {
    if(!new File(source).exists) {
      print("* initializing random source..")
      GeneratorTool.main(Array("vog", "", source, "/home/david/.verificatum_random_seed", "-rndinit", "RandomDevice", "/dev/urandom", "-v"))
    }
  }
}

// to tap System.out
class OutTap(val baos: ByteArrayOutputStream) extends PrintStream(baos) {  
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
