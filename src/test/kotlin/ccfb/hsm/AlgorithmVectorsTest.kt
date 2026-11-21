package ccfb.hsm

import ccfb.hsm.crypto.*
import ccfb.hsm.pin.*
import ccfb.hsm.model.*
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlin.test.assertFalse

/**
 * Known-answer tests against published vectors, plus cross-implementation checks.
 *
 * The PVV and CVV vectors are the public jPOS test vectors. They are the reason the rest of
 * the project can claim "this is what a real HSM computes" rather than "this is self
 * consistent".
 */
class AlgorithmVectorsTest {

    private fun hex(s: String) = Hex.decode(s)

    @Test
    fun `DES known answer`() {
        // NIST-style: DES(0102030405060708, 0000000000000000) == b073dc3fb209536d
        assertEquals("B073DC3FB209536D", Hex.encode(Des.encrypt(hex("0102030405060708"), ByteArray(8))))
    }

    @Test
    fun `2-key 3DES matches OpenSSL des-ede-ecb`() {
        // openssl enc -des-ede-ecb -K 0102030405060708090a0b0c0d0e0f10 on a zero block
        assertEquals(
            "AD17A7563A0FF8F3",
            Hex.encode(Tdes.encrypt(hex("0102030405060708090A0B0C0D0E0F10"), ByteArray(8)))
        )
    }

    @Test
    fun `3-key 3DES matches OpenSSL des-ede3`() {
        assertEquals(
            "C7B64CCCCDB0D304",
            Hex.encode(Tdes.encrypt(hex("0102030405060708090A0B0C0D0E0F101112131415161718"), ByteArray(8)))
        )
    }

    @Test
    fun `AES-128 zero vector`() {
        assertEquals(
            "66E94BD4EF8A2C3B884CFA59CA342B2E",
            Hex.encode(Aes.encrypt(ByteArray(16), ByteArray(16)))
        )
    }

    @Test
    fun `Visa PVV matches jPOS vector`() {
        // jPOS: PAN 1234567890123, PIN 1234, PVK 12345678 x2, PVKI 0 -> 1226
        val pvv = PinVerification.visaPvv("1234", "1234567890123", 0, hex("1234567812345678"))
        assertEquals("1226", pvv)
    }

    @Test
    fun `CVV matches jPOS vectors`() {
        // CVK = 12345678 repeated 4x, PAN 123456789012, exp 1108, svc 000 -> 204
        assertEquals(
            "204",
            CardVerification.cvv("123456789012", "1108", "000", hex("12345678123456781234567812345678"))
        )
        // Split CVK A/B (12345678 / 87654321) concatenated -> 453
        // jPOS cvkA clear = 1234567812345678, cvkB clear = 8765432187654321; concatenated
        // K1||K2 into a 2-key 3DES key -> CVV 453.
        assertEquals(
            "453",
            CardVerification.cvv("123456789012", "1108", "000", hex("12345678123456788765432187654321"))
        )
    }

    @Test
    fun `Visa decimalization is positional-independent as specified`() {
        // Digits are emitted first in order, then A-F mapped to 0-5. Not a positional map.
        assertEquals("012345", Decimalize.visa("012345"))
        // 6 digits then 6 letters -> 6 digits followed by 6 mapped values = 12 chars, not 6+6 concatenated
        assertEquals("012345012345", Decimalize.visa("012345ABCDEF"))
        // Interleaved: "0A1B" -> digits "01", then A->0, B->1 -> "0101"
        assertEquals("0101", Decimalize.visa("0A1B"))
        // The same input positional substitution would give is different:
        assertFalse(Decimalize.visa("0A1B") == "0011")
    }

    @Test
    fun `ISO-0 PIN block matches published vector`() {
        // eftlab: PAN 43219876543210987, PIN 1234 -> 0412AC89ABCDEF67
        val pinField = PinBlockCodec.pinField(PinFormat.ISO_0, "1234")
        assertEquals("041234FFFFFFFFFF", pinField)
        val panField = PinBlockCodec.panField12("43219876543210987")
        assertEquals("0000987654321098", panField)
        assertEquals("0412AC89ABCDEF67", PinBlockCodec.xorHex(pinField, panField))
    }

    @Test
    fun `ISO-1 and ISO-2 field layout`() {
        assertEquals("141234FFFFFFFFFF", PinBlockCodec.pinField(PinFormat.ISO_1, "1234"))
        assertEquals("241234FFFFFFFFFF", PinBlockCodec.pinField(PinFormat.ISO_2, "1234"))
    }

    @Test
    fun `ISO-3 uses random A-F fill`() {
        repeat(20) {
            val f = PinBlockCodec.pinField(PinFormat.ISO_3, "1234")
            assertEquals('3', f[0]); assertEquals('4', f[1])
            assertTrue(f.substring(6).all { it in 'A'..'F' }, "fill must be A-F: $f")
        }
    }

    @Test
    fun `ISO-4 field layout follows the PCI supplement`() {
        val f = PinBlockCodec.pinField(PinFormat.ISO_4, "1234")
        assertEquals(32, f.length)
        assertEquals("441234", f.substring(0, 6))
        assertTrue(f.substring(6, 16).all { it == 'A' })
        val pan = PinBlockCodec.panField4("432198765432109870")
        assertEquals("64321987654321098700000000000000", pan)
    }

    @Test
    fun `offset arithmetic is per digit mod 10`() {
        assertEquals("1111", PinVerification.computeOffset("1234", "0123"))
        assertEquals("1234", PinVerification.applyOffset("0123", "1111"))
        assertEquals("0000", PinVerification.computeOffset("9999", "9999"))
    }
}

/** Round-trip and structural-rejection tests for the codec. */
class PinBlockCodecTest {

    @Test
    fun `round trip every format`() {
        val pan = "4539578763627189"
        val pins = listOf("1234", "123456", "123456789012")
        for (format in PinFormat.entries) {
            for (pin in pins) {
                if (format == PinFormat.ISO_4 && pin.length > 12) continue
                val field = PinBlockCodec.pinField(format, pin)
                val decoded = PinBlockCodec.decodeField(format, field)
                assertEquals(pin, decoded.pin, "format=$format pin=$pin")
            }
        }
    }

    @Test
    fun `format 4 pan field handles short and long PANs`() {
        assertEquals("00000000000000000000000000000012", PinBlockCodec.panField4("12"))
        assertEquals("7" + "1234567890123456789" + "0".repeat(12), PinBlockCodec.panField4("1234567890123456789"))
    }

    @Test
    fun `rejects pin digit above nine`() {
        val bad = "04" + "1A34" + "F".repeat(10)
        val e = runCatching { PinBlockCodec.decodeField(PinFormat.ISO_0, bad) }.exceptionOrNull()
        assertTrue(e is PinBlockFormatException)
    }

    @Test
    fun `rejects wrong control nibble`() {
        val e = runCatching { PinBlockCodec.decodeField(PinFormat.ISO_1, "041234FFFFFFFFFF") }.exceptionOrNull()
        assertTrue(e is PinBlockFormatException, "ISO-1 must require control nibble 1")
    }

    @Test
    fun `rejects bad fill`() {
        val e = runCatching { PinBlockCodec.decodeField(PinFormat.ISO_0, "0412340000000000") }.exceptionOrNull()
        assertTrue(e is PinBlockFormatException)
    }

    @Test
    fun `rejects length below profile minimum`() {
        val profile = ValidationProfile("p", VerifyMethod.VISA_PVV, "k", minPinLength = 6)
        val e = runCatching { PinBlockCodec.decodeField(PinFormat.ISO_0, "041234FFFFFFFFFF", profile) }.exceptionOrNull()
        assertTrue(e is PinBlockFormatException)
    }

    @Test
    fun `rejects pin longer than field allows`() {
        val e = runCatching { PinBlockCodec.decodeField(PinFormat.ISO_0, "0D1234567890123456") }.exceptionOrNull()
        assertTrue(e is PinBlockFormatException, "13-digit PIN cannot fit a 16-nibble field")
    }
}
