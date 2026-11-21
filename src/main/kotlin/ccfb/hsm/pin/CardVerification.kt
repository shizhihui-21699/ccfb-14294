package ccfb.hsm.pin

import ccfb.hsm.crypto.Decimalize
import ccfb.hsm.crypto.Des
import ccfb.hsm.crypto.Hex
import ccfb.hsm.crypto.Tdes

/**
 * Card verification values.
 *
 *   CVV (CVV1 on track 2, iCVV from the chip) and CVV2 (printed) share the algorithm;
 *   they differ only in the data source and in key usage. This simulator computes the
 *   track-2 CVV and CVV2 for completeness and to demonstrate why a CVV oracle is dangerous.
 *
 *   data = PAN || expiry(YYMM) || service code  (right zero padded to 16 bytes)
 *   CVV  = first 3 decimalised digits of
 *            encrypt(CVK, encrypt(UDK-A, data[0..7]) xor data[8..15])
 *
 * Verified against jPOS public vectors: CVK 4x12345678 -> 204, CVK A/B split -> 453.
 *
 * Security note: CVVs are only 3 digits. Like PVVs they are returned to no caller; only
 * match/no-match is exposed and the attempt is metered.
 */
object CardVerification {

    fun cvv(pan: String, expiry: String, serviceCode: String, cvk: ByteArray): String {
        require(expiry.length == 4 && expiry.all { it in '0'..'9' })
        require(serviceCode.length == 3 && serviceCode.all { it in '0'..'9' })
        val data = (pan + expiry + serviceCode).padEnd(32, '0').take(32)
        if (!data.all { it in '0'..'9' }) throw IllegalArgumentException("non-decimal CVV input")
        val block = Hex.decode(data)
        val left = block.copyOfRange(0, 8)
        val right = block.copyOfRange(8, 16)
        val udkA = cvk.copyOfRange(0, 8)
        val step = Des.encrypt(udkA, left)
        val mixed = ByteArray(8) { i -> (step[i].toInt() xor right[i].toInt()).toByte() }
        val enc = if (cvk.size == 8) Des.encrypt(cvk, mixed) else Tdes.encrypt(cvk, mixed)
        return Decimalize.visa(Hex.encode(enc)).take(3)
    }
}
