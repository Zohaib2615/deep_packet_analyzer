import struct


class SNIExtractor:

    @staticmethod
    def read_uint16_be(data, offset):
        return struct.unpack("!H", data[offset:offset+2])[0]

    @staticmethod
    def read_uint24_be(data, offset):
        return int.from_bytes(data[offset:offset+3], "big")

    @staticmethod
    def is_tls_client_hello(payload):
        if len(payload) < 9:
            return False

        if payload[0] != 0x16:  # Handshake
            return False

        version = SNIExtractor.read_uint16_be(payload, 1)
        if version < 0x0300 or version > 0x0304:
            return False

        if payload[5] != 0x01:  # Client Hello
            return False

        return True

    @staticmethod
    def extract(payload):
        if not SNIExtractor.is_tls_client_hello(payload):
            return None

        offset = 5 + 4 + 2 + 32  # skip headers

        if offset >= len(payload):
            return None

        session_len = payload[offset]
        offset += 1 + session_len

        if offset + 2 > len(payload):
            return None

        cipher_len = SNIExtractor.read_uint16_be(payload, offset)
        offset += 2 + cipher_len

        if offset >= len(payload):
            return None

        comp_len = payload[offset]
        offset += 1 + comp_len

        if offset + 2 > len(payload):
            return None

        ext_len = SNIExtractor.read_uint16_be(payload, offset)
        offset += 2

        end = min(offset + ext_len, len(payload))

        while offset + 4 <= end:
            ext_type = SNIExtractor.read_uint16_be(payload, offset)
            ext_length = SNIExtractor.read_uint16_be(payload, offset + 2)
            offset += 4

            if ext_type == 0x0000:  # SNI
                if offset + 5 > len(payload):
                    return None

                sni_len = SNIExtractor.read_uint16_be(payload, offset + 3)
                return payload[offset + 5: offset + 5 + sni_len].decode(errors="ignore")

            offset += ext_length

        return None