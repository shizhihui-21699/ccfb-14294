package ccfb.hsm.pin

import ccfb.hsm.crypto.Decimalize
import ccfb.hsm.crypto.Des
import ccfb.hsm.crypto.Hex
import ccfb.hsm.model.ValidationProfile
import ccfb.hsm.model.VerifyMethod

/**
 * PIN verification algorithms.
 *
 * Both algorithms consume a *clear* PIN that the HSM recovered from a block it decrypted
 * with a key of usage PIN_VERIFICATION / PIN_ENCRYPTION. Neither the PIN, the natural PIN,
 * nor any intermediate value ever leaves this class.
 */
object PinVerification {

    /**
     * Visa PVV.
     *
     *   validation data = 11 rightmost PAN digits, excluding the check digit
     *                     || PVKI digit
     *                     || first 4 PIN digits
     *   PVV             = first 4 decimalised digits of DES-encrypt(PVK, validation data)
     *
     * Decimalisation is Visa's: take the decimal hex characters in order, then append
     * A-F mapped to 0-5. (Not a positional mapping — a subtle and frequently mis-implemented
     * distinction.) This is verified against the jPOS public vector: PAN 1234567890123,
     * PIN 1234, PVK 1234567812345678 -> PVV 1226.
     *
     * Why it is safe to expose the *result* of a PVV computation only as a boolean:
     * a PVV is 4 decimal digits. An attacker who could read PVVs back for chosen PINs could
     * build a table of 10^4 entries per card and recover the PIN with certainty. The service
     * therefore never returns a PVV; it only returns match/no-match, after the attempt is
     * counted and any lockout is applied.
     */
    fun visaPvv(pin: String, pan: String, pvki: Int, pvk: ByteArray): String {
        require(pin.length >= 4 && pin.all { it in '0'..'9' })
        require(pvki in 0..9)
        val panPart = pansForPvv(pan)
        val validation = panPart + pvki + pin.substring(0, 4)
        val data = Hex.decode(validation)
        val enc = if (pvk.size == 8) Des.encrypt(pvk, data) else ccfb.hsm.crypto.Tdes.encrypt(pvk, data)
        return Decimalize.visa(Hex.encode(enc)).take(4)
    }

    /** 11 rightmost digits of the PAN excluding the check digit. */
    fun pansForPvv(pan: String, padLength: Int = 11): String {
        require(pan.length >= 2)
        val withoutCheck = pan.dropLast(1)
        return if (withoutCheck.length >= padLength) {
            withoutCheck.takeLast(padLength)
        } else {
            withoutCheck.padStart(padLength, '0')
        }
    }

    /**
     * IBM 3624 natural PIN + offset.
     *
     *   validation data = PAN padded to 16 digits
     *   natural PIN     = first N decimalised digits of encrypt(PVK, validation data)
     *   offset          = (customer PIN - natural PIN) mod 10, per digit
     *
     * Verification recomputes the natural PIN and adds the stored offset; equal to the
     * submitted PIN means accept. The decimalisation table is taken from the *profile*,
     * never from a request.
     *
     * Known weakness, deliberately surfaced in the docs: an offset is not a keyed MAC of the
     * PIN. If the offset database leaks, the natural PIN is computable by anyone holding the
     * PAN and the PVK, and the offset directly yields the PIN. That is why this simulator
     * treats the offset as data which never crosses the API boundary.
     */
    fun ibm3624NaturalPin(
        pan: String,
        pinLength: Int,
        pvk: ByteArray,
        decimalizationTable: String,
        panPadChar: Char = '0'
    ): String {
        require(pinLength in 1..12)
        require(decimalizationTable.length == 16 && decimalizationTable.all { it in '0'..'9' })
        val vd = validationData3624(pan, panPadChar)
        val enc = if (pvk.size == 8) Des.encrypt(pvk, Hex.decode(vd)) else ccfb.hsm.crypto.Tdes.encrypt(pvk, Hex.decode(vd))
        val encHex = Hex.encode(enc)
        val sb = StringBuilder()
        for (c in encHex) {
            val idx = Character.digit(c, 16)
            sb.append(decimalizationTable[idx])
        }
        return sb.toString().take(pinLength)
    }

    fun validationData3624(pan: String, padChar: Char = '0'): String = pan.padEnd(16, padChar).take(16)

    fun computeOffset(pin: String, naturalPin: String): String {
        require(pin.length == naturalPin.length)
        val sb = StringBuilder()
        for (i in pin.indices) {
            sb.append(('0' + Math.floorMod(pin[i] - naturalPin[i], 10)))
        }
        return sb.toString()
    }

    fun applyOffset(naturalPin: String, offset: String): String {
        require(naturalPin.length == offset.length)
        val sb = StringBuilder()
        for (i in naturalPin.indices) {
            sb.append(('0' + Math.floorMod(naturalPin[i] - '0' + (offset[i] - '0'), 10)))
        }
        return sb.toString()
    }

    /** Returns true when the submitted PIN matches the card's stored verifier. */
    fun verify(
        profile: ValidationProfile,
        pin: String,
        pan: String,
        verifierValue: String?,
        pvk: ByteArray
    ): Boolean {
        if (verifierValue == null) return false
        return when (profile.method) {
            VerifyMethod.VISA_PVV -> {
                if (verifierValue.length != 4) return false
                val computed = visaPvv(pin, pan, profile.pvki, pvk)
                ccfb.hsm.crypto.ConstantTime.equals(computed, verifierValue)
            }
            VerifyMethod.IBM_3624_OFFSET -> {
                if (verifierValue.length != pin.length) return false
                val natural = ibm3624NaturalPin(pan, pin.length, pvk, profile.decimalizationTable, profile.panPadChar)
                val expected = applyOffset(natural, verifierValue)
                ccfb.hsm.crypto.ConstantTime.equals(expected, pin)
            }
        }
    }
}
