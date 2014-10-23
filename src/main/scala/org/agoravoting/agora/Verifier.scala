package org.agoravoting.agora

import scala.util.{Try, Success, Failure}
import java.io.{File, ByteArrayOutputStream, PrintStream}
import verificatum.ui.gen.GeneratorTool
import verificatum.protocol.mixnet.MixNetElGamalVerifyRO

// import java.security.MessageDigest
// import scala.math.BigInt
// import play.api.libs.json.Json
// import play.api.libs.json.JsArray

object Verifier extends App {

  if(args.length != 2) {
    println("verifier <random source> <tally directory>")
  } else if(new File(args(1)).exists) {
    // verifyPoks(args(1))
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
      GeneratorTool.main(Array("vog", "", source, "", "-rndinit", "RandomDevice", "/dev/urandom", "-v"))
    }
  }

  // parallel implementation of pok verification
  /* def verifyPoks(dir: String) = {
    val pk = io.Source.fromFile(dir + java.io.File.separator + "pubkeys_json").getLines.mkString
    val publicKeys = Json.parse(pk).asInstanceOf[JsArray].value

    val ct = io.Source.fromFile(dir + java.io.File.separator + "ciphertexts_json").getLines.toList
    val ctexts = ct.map(Json.parse).map(vote => {
      List((vote \ "proofs").asInstanceOf[JsArray].value,
      (vote \ "choices").asInstanceOf[JsArray].value,
      publicKeys).transpose
    })

    println("* verifying poks..")
    val t1 = System.currentTimeMillis();

    ctexts.par.foreach( vote => {
      vote.foreach( question => {

        val pk_p = BigInt((question(2) \ "p").as[String])
        val pk_g = BigInt((question(2) \ "g").as[String])

        val commitment = BigInt((question(0) \ "commitment").as[String])
        val response = BigInt((question(0) \ "response").as[String])
        val challenge = BigInt((question(0) \ "challenge").as[String])
        val alpha = BigInt((question(1) \ "alpha").as[String])

        val toHash = alpha + "/" + commitment
        val digest = MessageDigest.getInstance("SHA-256")
        val hash = digest.digest(toHash.getBytes("UTF-8"))
        val expected = BigInt(1, hash)

        assert (challenge == expected)

        val first_part = pk_g.modPow(response, pk_p)
        val second_part =  commitment * (alpha.modPow(challenge, pk_p)) % pk_p

        assert(first_part == second_part)
      })
    })

    val t2 = System.currentTimeMillis();
    println("* ok (poks) " + ((t2 - t1) / 1000.0))
  }*/
}

// to tap System.out
class OutTap(val baos: ByteArrayOutputStream) extends PrintStream(baos) {
  override def println(s: String) = {
//     super.println(s)
//     Console.println
  }
  override def print(s: String) = {
//     super.print(s)
//     Console.print(s"* $s")
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
