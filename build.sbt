name := "cruciform"

version := "0.9.0"

scalaVersion := "2.10.1"

resolvers += "Sonatype OSS Releases" at
  "http://oss.sonatype.org/content/repositories/releases/"

libraryDependencies ++= Seq(
    "commons-io" % "commons-io" % "2.4",
    "org.bouncycastle" % "bcprov-ext-jdk15on" % "1.50",
    "org.bouncycastle" % "bcpkix-jdk15on" % "1.50",
    "org.scalamock" % "scalamock-core_2.10" % "3.1.RC1" % "test",
    "org.scalamock" % "scalamock-scalatest-support_2.10" % "3.1.RC1" % "test",
    "org.scalatest" % "scalatest_2.10" % "2.1.0" % "test"
)
