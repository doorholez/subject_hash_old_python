def subject_hash_old(msg):
    def decode_b64(encoded_str: str) -> bytes:
        # base64 dict
        b64_chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
        char2num = {c:i for i, c in enumerate(b64_chars)}

        # count and strip padding '='
        n_padding = encoded_str.count('=')
        if n_padding > 2:
            raise ValueError("Number of padding '=' more than 2.")
        bits_padding = 2 * n_padding
        encoded_str = encoded_str.replace('\n', '')
        encoded_str = encoded_str.replace('\r', '')
        if len(encoded_str) % 4:
            raise ValueError(f"Invalid base64 string length: {len(encoded_str)}")
        encoded_str = encoded_str.rstrip('=')
        
        # translate base64 char to binary str
        invalid_chars = ''.join([c for c in encoded_str if c not in b64_chars])
        if len(invalid_chars):
            raise ValueError(f"Invalid base64 character: {invalid_chars}")
        binary_str = ''.join([format(char2num[c], '06b') for c in encoded_str if c in b64_chars])
        binary_str = binary_str[:-bits_padding]

        # translate binary str to bytes
        bytes_list = [int(binary_str[i:i+8], 2) for i in range(0, len(binary_str), 8)]
        return bytes(bytes_list)


    def der_parser(der_bytes):
        def _parse_tag(data, pos):
            tag = data[pos]
            pos += 1
            # multi-byte label
            if (tag & 0x1F) == 0x1F:
                while data[pos] & 0x80:
                    tag = (tag << 7) | (data[pos] & 0x7F)
                    pos += 1
            return tag, pos
        
        def _parse_length(data, pos):
            length = data[pos]
            pos += 1
            if length & 0x80:  # long format
                num_bytes = length & 0x7F
                length = int.from_bytes(data[pos:pos+num_bytes], 'big')
                pos += num_bytes
            return length, pos
        
        pos = 0
        rtn = []
        while pos < len(der_bytes):
            # read TLV structure
            tag, pos = _parse_tag(der_bytes, pos)
            length, pos = _parse_length(der_bytes, pos)
            value = der_bytes[pos:pos+length]
            pos += length
            rtn.append(value)
        return rtn


    def ASN1wrap(wrapped_item: str | bytes, wrapped_header: str | bytes):
        def demical2bytes(num: int) -> bytes:
            str_hex = hex(num)[2:]
            if len(str_hex) % 2 != 0:
                str_hex = '0' + str_hex
            return bytes.fromhex(str_hex)
        
        if type(wrapped_item) == str:
            wrapped_item = bytes.fromhex(wrapped_item)
        if type(wrapped_header) == str:
            wrapped_header = bytes.fromhex(wrapped_header)
        length = len(wrapped_item)
        if length < 128:
            wrapped_length = demical2bytes(length)
        else:
            wrapped_length = demical2bytes(length)
            length_bytes = len(wrapped_length)
            wrapped_length = demical2bytes(0x80 + length_bytes) + wrapped_length
        return wrapped_header + wrapped_length + wrapped_item


    def padding(msg: bytes) -> bytes:
        len_msg = (8 * len(msg)) & 0xffffffffffffffff
        # pad bits to msg that len(msg) % 64 == 56 (bit of msg % 512 == 448)
        msg += bytes.fromhex('80')
        msg += bytes((56 - (len(msg) % 64)) % 64)
        
        # append 64-bits (8-bytes) little endian length of original msg
        msg += len_msg.to_bytes(8, byteorder='little')
        return msg


    def process_msg(msg: bytes) -> list[int]:
        # def left rotate helper function
        def left_rotate(x, s):
            x &= 0xffffffff
            return (x << s | x >> (32 - s))
        
        # initialise md_buffer
        md_buffer = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476]

        # initialse add constant t
        t = [0xD76AA478,0xE8C7B756,0x242070DB,0xC1BDCEEE,0xF57C0FAF,0x4787C62A,0xA8304613,0xFD469501,
            0x698098D8,0x8B44F7AF,0xFFFF5BB1,0x895CD7BE,0x6B901122,0xFD987193,0xA679438E,0x49B40821,
            0xF61E2562,0xC040B340,0x265E5A51,0xE9B6C7AA,0xD62F105D,0x02441453,0xD8A1E681,0xE7D3FBC8,
            0x21E1CDE6,0xC33707D6,0xF4D50D87,0x455A14ED,0xA9E3E905,0xFCEFA3F8,0x676F02D9,0x8D2A4C8A,
            0xFFFA3942,0x8771F681,0x6D9D6122,0xFDE5380C,0xA4BEEA44,0x4BDECFA9,0xF6BB4B60,0xBEBFBC70,
            0x289B7EC6,0xEAA127FA,0xD4EF3085,0x04881D05,0xD9D4D039,0xE6DB99E5,0x1FA27CF8,0xC4AC5665,
            0xF4292244,0x432AFF97,0xAB9423A7,0xFC93A039,0x655B59C3,0x8F0CCC92,0xFFEFF47D,0x85845DD1,
            0x6FA87E4F,0xFE2CE6E0,0xA3014314,0x4E0811A1,0xF7537E82,0xBD3AF235,0x2AD7D2BB,0xEB86D391]
        
        # initialise rotate constant s
        s = [7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
            5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20,
            4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
            6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21]

        # process block of 512 bits (64 bytes)
        for msg_i in range(0, len(msg), 64):
            A, B, C, D = md_buffer[:]
            block = msg[msg_i: msg_i + 64]

            # block processed as 16x 32-bit (4-byte) chunks
            for round in range(64):
                if round < 16: # 0-15 rounds
                    func = lambda b,c,d: (b & c) | (~b & d)
                    index_chunk = round
                elif round < 32: # 16-31 rounds
                    func = lambda b,c,d: (b & d) | (~d & c)
                    index_chunk = (5 * round + 1) % 16
                elif round < 48: # 32-47 rounds
                    func = lambda b,c,d: b ^ c ^ d
                    index_chunk = (3 * round + 5) % 16
                elif round < 64: # 48-63 rounds
                    func = lambda b,c,d: c ^ (b | ~d)
                    index_chunk = (7 * round) % 16
                
                chunk = block[index_chunk * 4: index_chunk * 4 + 4]
                to_rotate = A + func(B, C, D) + int.from_bytes(chunk, 'little') + t[round]
                A = (left_rotate(to_rotate, s[round]) + B) & 0xffffffff
                A, B, C, D = D, A, B, C
            
            # add the result of the processed block to md_buffer
            for i, val in enumerate([A, B, C, D]):
                md_buffer[i] += val
                md_buffer[i] &= 0xffffffff
        
        return md_buffer
    
    if "-----BEGIN CERTIFICATE-----" not in msg: # input file path
        with open(msg) as f:
            msg = f.read()
    
    # remove certificate header and tail
    msg = msg.replace("-----BEGIN CERTIFICATE-----", "")
    msg = msg.replace("-----END CERTIFICATE-----", "")
    
    # decode base64 string into bytes
    msg = decode_b64(msg)

    # get subject name bytes
    msg = ASN1wrap(der_parser(der_parser(der_parser(msg)[0])[0])[5], '30')

    # calculate MD5 hash and get big endian first 4 bytes as file name
    return f"{process_msg(padding(msg))[0]:08x}"


if __name__ == "__main__":
    print("请将证书的完整内容或是证书的路径粘贴在这里并按下回车：")
    print("Please paste the complete certificate content or the certificate path here and press Enter:")
    msg = []
    while True:
        line = input()
        if line:
            msg.append(line)
        else:
            break
    msg = ''.join(msg)
    # print(msg)
    name = subject_hash_old(msg)
    print("证书应该被命名为：")
    print("The certificate should be named as: ")
    print(f"{name}.0")
