name := "agora-verifier"

version := "1.0"

scalaVersion := "2.10.3"

mainClass := Some("org.agoravoting.agora.Verifier")

javaOptions in run += "-Djava.security.egd=file:/dev/./urandom"

fork in run := true

// libraryDependencies += "com.typesafe.play" %% "play-json" % "2.2.1"

// resolvers += "Typesafe repository" at "http://repo.typesafe.com/typesafe/releases/"

proguardSettings

ProguardKeys.options in Proguard ++= Seq("-dontnote", "-dontwarn", "-ignorewarnings")

ProguardKeys.options in Proguard += ProguardOptions.keepMain("org.agoravoting.agora.Verifier")

ProguardKeys.options in Proguard += "-keep class verificatum.crypto.RandomDevice { *; }"

ProguardKeys.options in Proguard += "-keep class verificatum.arithm.ModPGroup { *; }"

ProguardKeys.options in Proguard += "-keep class verificatum.crypto.RandomDeviceGen { *; }"