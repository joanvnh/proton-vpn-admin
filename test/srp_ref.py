#!/usr/bin/env python3
"""Independent Python reference of the SRP math, translated directly from
ProtonMail/go-srp (srp.go + hash.go). Used to cross-check the JS port."""
import hashlib, base64, json, sys

def expand_hash(data: bytes) -> bytes:
    return b''.join(hashlib.sha512(data + bytes([i])).digest() for i in range(4))

def le_to_int(b: bytes) -> int:
    return int.from_bytes(b, 'little')

def int_to_le(n: int, ln: int) -> bytes:
    return n.to_bytes(ln, 'little')

# Test modulus from go-srp srp_test.go (base64, little-endian wire format)
MOD_B64 = ("W2z5HBi8RvsfYzZTS7qBaUxxPhsfHJFZpu3Kd6s1JafNrCCH9rfvPLrfuqocxWPgWDH2R8neK7PkNvjxto9TStuY5z7jAz"
           "WRvFWN9cQhAKkdWgy0JY6ywVn22+HFpF4cYesHrqFIKUPDMSSIlWjBVmEJZ/MusD44ZT29xcPrOqeZvwtCffKtGAIjLYPZIEbZKnDM1Dm3q2K/"
           "xS5h+xdhjnndhsrkwm9U9oyA2wxzSXFL+pdfj2fOdRwuR5nW0J2NFrq3kJjkRmpO/Genq1UW+TEknIWAb6VzJJJA244K/H8cnSx2+nSNZO3bbo6Ys228ruV9A8m6DhxmS+bihN3ttQ==")
SRV_EPH_B64 = ("l13IQSVFBEV0ZZREuRQ4ZgP6OpGiIfIjbSDYQG3Yp39FkT2B/k3n1ZhwqrAdy+qvPPFq/le0b7UDtayoX4aOTJihoRvifas8Hr3icd9nAHqd0TUBbkZkT6Iy6UpzmirCXQtEhvGQIdOLuwvy+"
               "vZWh24G2ahBM75dAqwkP961EJMh67/I5PA5hJdQZjdPT5luCyVa7BS1d9ZdmuR0/VCjUOdJbYjgtIH7BQoZs+KacjhUN8gybu+fsycvTK3eC+9mCN2Y6GdsuCMuR3pFB0RF9eKae7cA6RbJfF1bjm0nNfWLXzgKguKBOeF3GEAsnCgK68q82/pq9etiUDizUlUBcA==")

def main():
    mod_le = base64.b64decode(MOD_B64)
    N = le_to_int(mod_le)
    assert N.bit_length() == 2048 and N % 8 == 3, "modulus sanity"
    srv = base64.b64decode(SRV_EPH_B64)
    b = le_to_int(srv)
    assert 1 < b < N - 1

    # fixed test x and a (bypass bcrypt; bcrypt is verified separately via Go vectors)
    x = le_to_int(expand_hash(b"fixed-x-test-vector"))
    k = le_to_int(expand_hash(int_to_le(2, 256) + mod_le)) % N
    a = (1 << 2000) + 99999
    assert 4096 < a < N - 1

    A = pow(2, a, N)
    Ab = int_to_le(A, 256)
    u = le_to_int(expand_hash(Ab + srv))
    assert u != 0
    base = (b - (k * pow(2, x, N)) % N) % N
    S = pow(base, (u * x + a) % (N - 1), N)
    Sb = int_to_le(S, 256)
    M1 = expand_hash(Ab + srv + Sb)
    M2 = expand_hash(Ab + M1 + Sb)

    out = {
        "mod_b64": MOD_B64,
        "srv_eph_b64": SRV_EPH_B64,
        "A": base64.b64encode(Ab).decode(),
        "M1": base64.b64encode(M1).decode(),
        "M2": base64.b64encode(M2).decode(),
        "x_b64": base64.b64encode(int_to_le(x, 256)).decode(),
        "a_dec": str(a),
        "expand_hash_hello": base64.b64encode(expand_hash(b"hello")).decode(),
    }
    json.dump(out, open(sys.argv[1], "w"), indent=1)
    print("python reference written")

if __name__ == "__main__":
    main()
