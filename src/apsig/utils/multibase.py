import base64

BASE58BTC_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

def base64_url_no_pad_encode(data: bytes) -> str:
    encoded = base64.urlsafe_b64encode(data).rstrip(b'=').decode('utf-8')
    return 'u' + encoded

def base58btc_encode(data: bytes) -> str:
    num = int.from_bytes(data, 'big')
    encoded = []

    while num > 0:
        num, rem = divmod(num, 58)
        encoded.append(BASE58BTC_ALPHABET[rem])

    for byte in data:
        if byte == 0:
            encoded.append(BASE58BTC_ALPHABET[0])
        else:
            break

    encoded.reverse()
    return 'z' + ''.join(encoded)

def multibase_encode(data: bytes, base: str) -> str:
    if base == 'base64url':
        return base64_url_no_pad_encode(data)
    elif base == 'base58btc':
        return base58btc_encode(data)
    else:
        raise ValueError("Unsupported base type")

def base64_url_no_pad_decode(encoded: str) -> bytes:
    padding_needed = 4 - (len(encoded) % 4)
    if padding_needed < 4:
        encoded += '=' * padding_needed
    return base64.urlsafe_b64decode(encoded)

def base58_decode(encoded: str) -> bytes:
    num = 0
    for char in encoded:
        num *= 58
        num += BASE58BTC_ALPHABET.index(char)
    
    combined = num.to_bytes((num.bit_length() + 7) // 8, 'big')
    return combined

def multibase_decode(encoded: str) -> bytes:
    prefix = encoded[0]
    payload = encoded[1:]

    if prefix == 'u':
        return base64_url_no_pad_decode(payload)
    elif prefix == 'z':
        return base58_decode(payload)
    else:
        raise ValueError("Unsupported multibase prefix")