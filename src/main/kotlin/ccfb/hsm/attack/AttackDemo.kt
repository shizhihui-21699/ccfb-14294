package ccfb.hsm.attack

import ccfb.hsm.demo.DemoEnv
import ccfb.hsm.model.ErrorCode
import java.io.PrintStream

/**
 * Entry point for the attack demonstration: `gradle attackDemo`.
 *
 * It prints, for every probe, what was attempted, why the control that stopped it exists,
 * and whether anything leaked. Probes that are *supposed* to succeed (the offline PVV
 * recovery control, the database-inspection control) are labelled `CONTROL` so that a reader
 * can see the difference between "we stopped this" and "this is why the design has to keep
 * the verifier inside the HSM".
 */
fun main() {
    val out = System.out
    out.println("=".repeat(100))
    out.println("PIN HSM simulator — adversarial probe suite")
    out.println("=".repeat(100))
    out.println()

    val env = DemoEnv().build()
    env.provision(
        env.cardVisa to "7315",
        env.cardOffset to "4826",
        env.cardAes to "9043"
    )
    // The acquirer must be allowed to verify on behalf of the issuer in this demo.
    env.hsm.allowVerificationKey("pvk.visa", "acq.host")
    env.hsm.allowVerificationKey("pvk.ibm", "acq.host")

    val suite = AttackSuite(env)
    suite.a1TamperedVerificationParams()
    suite.a2AccountSwap()
    suite.a3FormatRelabel()
    suite.b1ConversionOracle()
    suite.b2StripBinding()
    suite.b3VerificationKeyAsCipherKey()
    suite.c1SingleClientBruteForce()
    suite.c2DistributedProbe()
    suite.c3ConcurrentBurst()
    suite.c4OfflinePvvRecovery()
    suite.d1Replay()
    suite.d2Forgery()
    suite.d3KeyUsageConfusion()
    suite.d4NonceExhaustion()
    suite.d5ErrorOracle()
    suite.d6OfflineFormatOnline()
    suite.d7DatabaseInspection()

    report(out, suite)
}

fun report(out: PrintStream, suite: AttackSuite) {
    val controls = suite.results.filterNot { it.id == "C4" || it.id == "D7" }
    val controlsOk = controls.all { !it.leaked }
    out.println("-".repeat(100))
    out.printf("%-4s %-8s %s%n", "ID", "VERDICT", "ATTACK")
    out.println("-".repeat(100))
    for (r in suite.results) {
        val verdict = when {
            r.id == "C4" || r.id == "D7" -> if (r.leaked) "CONTROL" else "NO-LEAK"
            r.leaked -> "LEAKED"
            else -> "BLOCKED"
        }
        out.printf("%-4s %-8s %s%n", r.id, verdict, r.attack)
        out.println("       tried : ${r.attempted}")
        out.println("       why   : ${r.blockedBy}")
        out.println()
    }
    out.println("-".repeat(100))
    out.println("Summary: ${suite.results.size} probes; controls that must leak: " +
        suite.results.filter { it.id == "C4" || it.id == "D7" }.count { it.leaked })
    out.println("Every attack that targets the protocol was blocked: $controlsOk")
    out.println("-".repeat(100))
    if (!controlsOk) {
        throw IllegalStateException("an attack succeeded: " +
            controls.filter { it.leaked }.joinToString { it.id })
    }
}
