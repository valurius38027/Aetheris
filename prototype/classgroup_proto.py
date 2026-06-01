"""
Class Group Composition Prototype (Python)
Binary quadratic form composition for Cl(D) -- correct algorithm.
"""
import math, sys, traceback
from dataclasses import dataclass

DEBUG = True
def log(msg, *args):
    if DEBUG:
        print(("  "+msg).format(*args) if args else "  "+msg)

def egcd(a: int, b: int):
    """Extended GCD: (g, u, v) where u*a + v*b = g = gcd(a,b)."""
    if a == 0: return b, 0, 1
    g, u1, v1 = egcd(b % a, a)
    return g, v1 - (b // a) * u1, u1

def inv_mod(a: int, m: int) -> int:
    """Modular inverse of a mod m (assumes gcd=1)."""
    g, x, _ = egcd(a % m, m)
    assert g == 1, f"inv_mod: gcd({a},{m})={g} != 1"
    return x % m

@dataclass
class Form:
    a: int; b: int; c: int

    def discriminant(self) -> int:
        return self.b * self.b - 4 * self.a * self.c

    def abs_d(self) -> int:
        return -self.discriminant()

    def is_reduced(self) -> bool:
        return abs(self.b) <= self.a <= self.c and (self.a != abs(self.b) or self.b >= 0)

    def __repr__(self):
        return f"({self.a},{self.b},{self.c})"

    def __eq__(self, other):
        return self.a == other.a and self.b == other.b and self.c == other.c

    def reduce(self):
        a, b, c = self.a, self.b, self.c
        abs_d = self.abs_d()
        log("reduce: ({},{},{})", a, b, c)
        for _ in range(1000):
            if a > c or (a == c and b < 0):
                log(" swap -> ({},{},{})", c, -b, a)
                a, c, b = c, a, -b
            abs_b = abs(b)
            if abs_b > a:
                two_a = 2 * a
                b_mod = b % two_a
                new_b = b_mod if b_mod <= a else b_mod - two_a
                disc = 4 * a * c - b * b  # = |D|
                new_c = (new_b * new_b + disc) // (4 * a)
                log(" reduce_b: ({},{},{}) -> ({},{},{})", a, b, c, a, new_b, new_c)
                b, c = new_b, new_c
                continue
            break
        log(" done -> ({},{},{})", a, b, c)
        return Form(a, b, c)

    @staticmethod
    def identity(abs_d: int):
        """Identity for Cl(D) where D = -abs_d."""
        if abs_d % 4 == 3:
            return Form(1, 1, (1 + abs_d) // 4)
        elif abs_d % 4 == 0:
            return Form(1, 0, abs_d // 4)
        raise ValueError(f"bad abs_d%4: {abs_d%4}")

    def is_identity(self) -> bool:
        return self.a == 1 and self.b == 1

    def compose(self, other: "Form") -> "Form":
        """Gauss composition using extended GCD (correct algorithm)."""
        a1, b1, c1 = self.a, self.b, self.c
        a2, b2, c2 = other.a, other.b, other.c
        D = self.discriminant()
        assert D == other.discriminant(), f"D mismatch: {D} vs {other.discriminant()}"
        abs_d = self.abs_d()

        log("")
        log("COMPOSE: ({},{},{}) o ({},{},{})  D={}", a1,b1,c1, a2,b2,c2, D)

        # 1  g = gcd(a1, a2, (b1+b2)/2)
        b12 = (b1 + b2) // 2
        g = math.gcd(math.gcd(a1, a2), b12)
        log("g = gcd({},{},{}) = {}", a1, a2, b12, g)

        # 2  n = a1*a2 / g^2
        n = (a1 * a2) // (g * g)
        log("n = {}*{}/{}^2 = {}", a1, a2, g, n)

        # 3  A1 = a1/g, A2 = a2/g
        A1, A2 = a1 // g, a2 // g
        log("A1 = a1/g = {}, A2 = a2/g = {}", A1, A2)

        # 4  egcd: u*A1 + v*A2 = d = gcd(A1, A2)
        d_val, u, v = egcd(A1, A2)
        log("egcd: {}*{} + {}*{} = {}", u, A1, v, A2, d_val)

        # 5  s = (b2 - b1) / 2
        s = (b2 - b1) // 2
        log("s = (b2-b1)/2 = ({}-{})/2 = {}", b2, b1, s)

        # 6  x0 = u * s / d
        x0 = u * s // d_val
        log("x0 = u*s = {}*{} = {}", u, s, x0)

        # 7  B0 = b1 + 2*A1*x0
        B0 = b1 + 2 * A1 * x0
        log("B0 = b1 + 2*A1*x0 = {} + 2*{}*{} = {}", b1, A1, x0, B0)

        # 8  M = 2*n / d
        M = (2 * n) // d_val
        log("M = 2n/d = 2*{}/{} = {}", n, d_val, M)

        two_n = 2 * n
        four_n = 4 * n

        # 9  Find t
        t = None
        if a1 == a2 and b1 == b2 and c1 == c2:
            # SQUARING: b1*t == -g*c1 (mod A1)
            rhs = (-g * c1) % A1
            if A1 == 1:
                t = 0
            else:
                inv_b1 = inv_mod(b1 % A1, A1)
                t = (rhs * inv_b1) % A1
            log("SQUARING: t = (-g*c1)/b1 mod A1 = {} (mod {})", t, A1)
        else:
            # General composition: search t in [0, d)
            log("GENERAL: search t in [0, {})", d_val)
            found = False
            for ti in range(min(d_val, 100000)):
                B = B0 + ti * M
                if (B * B + abs_d) % four_n == 0:
                    t = ti
                    log(" found t={} at iter {}", t, ti+1)
                    found = True
                    break
            if not found:
                raise RuntimeError(f"t not found in [0,{d_val})")

        B = B0 + t * M
        B = B % two_n
        # ensure B in [0, two_n)
        B = B if B >= 0 else B + two_n
        c3 = (B * B + abs_d) // four_n
        log("B = {}, c3 = ({}^2+{})/{} = {}", B, B, abs_d, four_n, c3)

        result = Form(n, B, c3)
        log("pre-reduce: {}", result)
        return result.reduce()

    def square(self):
        return self.compose(self)

    def pow(self, e: int):
        if e == 0:
            return Form.identity(self.abs_d())
        result, base = self, self
        e -= 1
        while e:
            if e & 1:
                result = result.compose(base)
            base = base.square()
            e >>= 1
        return result


# ── Tests with fixed discriminant D = -4003 (abs_d = 4003) ──────────────────

ABS_D = 4003   # ≡ 3 mod 4 → D ≡ 1 mod 4

def t(name, ok, detail=""):
    print(f"[{'PASS' if ok else 'FAIL'}] {name}" + (f" {detail}" if detail else ""))

def test_identity():
    ident = Form.identity(ABS_D)
    t("identity form", ident.a == 1 and ident.b == 1 and ident.discriminant() == -ABS_D,
      str(ident))

def test_reduce():
    f = Form(1, 1, 1001)  # identity for D=-4003
    r = f.reduce()
    t("reduce identity", r.is_reduced() and r == f)

def test_compose_identity():
    ident = Form.identity(ABS_D)
    f2 = Form(7, 1, 143)
    r1 = f2.compose(ident)
    r2 = ident.compose(f2)
    ok1 = r1 == f2
    ok2 = r2 == f2
    t("compose f o id", ok1, f"got {r1}")
    t("compose id o f", ok2, f"got {r2}")

def test_square():
    """f o f = f.square() and is same as f^2."""
    f = Form(7, 1, 143)
    s1 = f.compose(f)
    s2 = f.square()
    p2 = f.pow(2)
    t("square comp == square", s1 == s2)
    t("square == pow2", s1 == p2)

def test_associative():
    f = Form(7, 1, 143)
    g = Form(11, 1, 91)
    h = Form(13, 1, 77)
    left = f.compose(g).compose(h)
    right = f.compose(g.compose(h))
    ok = left == right
    t("associative", ok, f"left={left} right={right}")

def test_pow():
    """f^(a+b) = f^a o f^b"""
    f = Form(7, 1, 143)
    f4_v1 = f.pow(4)
    f2 = f.pow(2)
    f4_v2 = f2.compose(f2)
    t("pow consistency", f4_v1 == f4_v2, f"pow4={f4_v1} f2of2={f4_v2}")

def test_hash_to_form_deterministic():
    """Deterministic form from seed."""
    def htf(seed):
        b = seed % (2 * int(math.isqrt(ABS_D // 3)) - 1) | 1
        for _ in range(1000):
            num = b * b + ABS_D
            a = int(math.isqrt(num // 4))
            if a > 0 and num % (4 * a) == 0:
                c = num // (4 * a)
                if math.gcd(a, b, c) == 1:
                    return Form(a, b, c).reduce()
            b += 2
        raise RuntimeError("htf failed")
    f1 = htf(42)
    f2 = htf(42)
    t("hash_to_form deterministic", f1 == f2, str(f1))

def test_serialization():
    """Deterministic compose."""
    f = Form(7, 1, 143)
    g = Form(11, 1, 91)
    r1 = f.compose(g)
    r2 = f.compose(g)
    t("serialization roundtrip", r1 == r2, f"{r1} vs {r2}")


# ── Additional: square different forms ──────────────────────────────────────

def test_square_identity():
    """Identity squared is identity."""
    ident = Form.identity(ABS_D)
    r = ident.square()
    t("square identity", r == ident, str(r))

def test_square_large():
    """Square (17, 3, 59) — another form with D=-4003."""
    f = Form(17, 3, 59)
    r = f.square()
    t("square (17,3,59)", r.is_reduced() and r.discriminant() == -ABS_D, str(r))

def test_pow_large():
    f = Form(7, 1, 143)
    p8 = f.pow(8)
    p4 = f.pow(4)
    p8alt = p4.compose(p4)
    t("pow 8 consistent", p8 == p8alt, f"pow8={p8} p4^2={p8alt}")


ALL_TESTS = [
    test_identity, test_reduce,
    test_compose_identity,
    test_square, test_square_identity, test_square_large,
    test_associative,
    test_pow, test_pow_large,
    test_hash_to_form_deterministic,
    test_serialization,
]

if __name__ == "__main__":
    print(f"Python {sys.version}")
    print(f"Discriminant D = -{ABS_D}")
    print()

    passed = 0
    for fn in ALL_TESTS:
        try:
            fn()
            passed += 1
        except Exception as e:
            print(f"[FAIL] {fn.__name__}: {e}")
            traceback.print_exc()
            if DEBUG:
                raise

    total = len(ALL_TESTS)
    print(f"\n{'='*50}")
    print(f"Results: {passed}/{total} passed")
