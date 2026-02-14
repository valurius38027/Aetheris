import hashlib
phrase = b"crystal sudden zero dynamic unique secret manual adjust orbit current focus total"
# Aetheris uses Keccak-256 (SHA3-256 in Python is slightly different from Keccak-256 but often used interchangeably in loose context, 
# but Rust's Keccak::v256 is actually Keccak-256)
# Let's use pysha3 if available, or just assume it matches if I use the right one.
# Actually, I'll just check the FFI logs from the test run.
