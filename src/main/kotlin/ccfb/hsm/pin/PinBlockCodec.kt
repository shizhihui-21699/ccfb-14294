package ccfb.hsm.pin

import ccfb.hsm.crypto.Hex
import ccfb.hsm.crypto.RandomBytes
import ccfb.hsm.model.PinFormat
import ccfb.hsm.model.ValidationProfile

/** Recovered PIN plus its length. */
data class DecodedPin(val pin: String, val length: Int)

/** Every content-dependent PIN block failure. Callers must collapse this to one public error. */
class PinBlockFormatException(message: String) : RuntimeException(message)

/**
 * Strict ISO 9564 PIN block field codec.
 *
 * The codec works in **nibble fields**, not whole blocks, because that is the only way to
 * keep formats 0/3 (XOR-binding) and format 4 (two-pass AES) honest:
 *
 *   format 0/3: block = PINfield XOR PANfield
 *   format 1/2: block = PINfield                       (no PAN binding at all)
 *   format 4  : A = Enc(PINfield); B = A XOR PANfield; C = Enc(B)
 *
 * Splitting the two fields here means the service layer can never accidentally treat the
 * XOR of a format 4 block as a plaintext PIN field — a bug class that turns an AES block
 * into a TDEA-format oracle.
 */
object PinBlockCodec {

    private val DECIMAL = Regex("[0-9]+")

    fun requireValidPin(pin: String, profile: ValidationProfile? = null) {
        val min = profile?.minPinLength ?: 4
        val max = profile?.maxPinLength ?: 12
        if (!DECIMAL.matches(pin)) throw PinBlockFormatException("PIN must be decimal")
        if (pin.length !in min..max) throw PinBlockFormatException("PIN length out of range")
    }

    // ------------------------------------------------------------------ fields

    /**
     * Plaintext PIN field.
     *
     *   format 0: 0 L P..P F..F  (16 nibbles)
     *   format 1: 1 L P..P F..F  (16 nibbles, transaction field optional upstream)
     *   format 2: 2 L P..P F..F  (16 nibbles)
     *   format 3: 3 L P..P R..R  (random A-F fill)
     *   format 4: 4 L P..P A..A R..R (32 nibbles; A fill then 16 random nibbles)
     */
    fun pinField(format: PinFormat, pin: String): String {
        requireValidPin(pin)
        val sb = StringBuilder()
        val control = when (format) {
            PinFormat.ISO_0 -> '0'
            PinFormat.ISO_1 -> '1'
            PinFormat.ISO_2 -> '2'
            PinFormat.ISO_3 -> '3'
            PinFormat.ISO_4 -> '4'
        }
        sb.append(control).append("%X".format(pin.length)).append(pin)
        when (format) {
            PinFormat.ISO_3 -> while (sb.length < 16) sb.append(('A'.code + RandomBytes.int(6)).toChar())
            PinFormat.ISO_4 -> {
                while (sb.length < 16) sb.append('A')
                repeat(16) { sb.append(RandomBytes.hex(1)) }
            }
            else -> while (sb.length < 16) sb.append('F')
        }
        return sb.toString()
    }

    /** PAN field: `0000` + 12 rightmost PAN digits excluding the check digit. Null for 1/2/4. */
    fun panField12(pan: String?): String {
        val p = pan ?: throw PinBlockFormatException("PAN required")
        if (p.length < 13 || !DECIMAL.matches(p)) throw PinBlockFormatException("bad PAN")
        return "0000" + p.substring(p.length - 13, p.length - 1)
    }

    /**
     * ISO-4 PAN field (32 nibbles): M | PAN(<=15) | 0-pad | 16 zero nibbles.
     * M = PAN length - 12 for 12..19 digit PANs; for shorter PANs M is 0 and the digits are
     * right-justified in the 16-nibble area.
     */
    fun panField4(pan: String?): String {
        val p = pan ?: throw PinBlockFormatException("PAN required")
        if (!DECIMAL.matches(p)) throw PinBlockFormatException("bad PAN")
        if (p.length > 19) throw PinBlockFormatException("bad PAN")
        // M | PAN | zero pad. The figure is 128 bits wide, so an 18-19 digit PAN legitimately
        // runs past the first 16 nibbles; the only real constraint is PAN length <= 19.
        return if (p.length < 12) {
            p.padStart(32, '0')
        } else {
            ("%X".format(p.length - 12) + p).padEnd(32, '0')
        }
    }

    fun panFieldOf(format: PinFormat, pan: String?): String? = when (format) {
        PinFormat.ISO_0, PinFormat.ISO_3 -> panField12(pan)
        PinFormat.ISO_4 -> panField4(pan)
        PinFormat.ISO_1, PinFormat.ISO_2 -> null
    }

    /** Assembles the 8- or 16-byte clear block input for the block cipher. */
    fun clearBlock(format: PinFormat, pinField: String, panField: String?): String =
        if (panField == null) pinField else xorHex(pinField, panField)

    // ------------------------------------------------------------------ decoding

    /**
     * Decodes a plaintext PIN field that the HSM itself recovered.
     *
     * [expectedPan] is the PAN resolved from the card record (never from a request). For
     * format 4 it is used to rebuild the PAN field; for 0/3 the caller has already XORed it
     * out, so [field] is the recovered PIN field.
     */
    fun decodeField(format: PinFormat, field: String, profile: ValidationProfile? = null): DecodedPin {
        val expectedControl = when (format) {
            PinFormat.ISO_0 -> '0'
            PinFormat.ISO_1 -> '1'
            PinFormat.ISO_2 -> '2'
            PinFormat.ISO_3 -> '3'
            PinFormat.ISO_4 -> '4'
        }
        if (field.length != format.hexLen) throw PinBlockFormatException("wrong field length")
        if (!field.all { Hex.isHexDigit(it) }) throw PinBlockFormatException("not hex")
        if (field[0] != expectedControl) throw PinBlockFormatException("control nibble mismatch")

        val lenNibble = field[1]
        if (lenNibble !in '4'..'9' && lenNibble != 'A' && lenNibble != 'B' && lenNibble != 'C') {
            throw PinBlockFormatException("bad length nibble")
        }
        val len = lenNibble.digitToInt(16)
        val min = profile?.minPinLength ?: 4
        val max = profile?.maxPinLength ?: 12
        if (len !in min..max) throw PinBlockFormatException("length outside profile")
        val digits = field.substring(2, 2 + len)
        if (!digits.all { it in '0'..'9' }) throw PinBlockFormatException("PIN digit above 9")

        // Fill rules: format 0/1/2 must be 'F'; format 3 must be A-F; format 4 must be 'A'
        // up to nibble 16, and is random beyond it.
        val fillEnd = if (format == PinFormat.ISO_4) 16 else field.length
        for (i in (2 + len) until fillEnd) {
            val c = field[i]
            when (format) {
                PinFormat.ISO_0, PinFormat.ISO_1, PinFormat.ISO_2 ->
                    if (c != 'F') throw PinBlockFormatException("bad fill nibble")
                PinFormat.ISO_3 ->
                    if (c !in 'A'..'F') throw PinBlockFormatException("bad fill nibble")
                PinFormat.ISO_4 ->
                    if (c != 'A') throw PinBlockFormatException("bad fill nibble")
            }
        }
        return DecodedPin(digits, len)
    }

    fun xorHex(a: String, b: String): String {
        if (a.length != b.length) throw PinBlockFormatException("length mismatch")
        val sb = StringBuilder(a.length)
        for (i in a.indices) {
            val x = Character.digit(a[i], 16)
            val y = Character.digit(b[i], 16)
            if (x < 0 || y < 0) throw PinBlockFormatException("not hex")
            sb.append("%X".format(x xor y))
        }
        return sb.toString()
    }
}
