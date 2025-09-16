from flask import Flask, render_template, request, redirect, url_for, session, jsonify
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
from uqrng_direct.client import UqrngClient
import os, time, hashlib, threading

app = Flask(__name__)
app.secret_key = os.urandom(24)

# -----------------------------
# CONFIG
# -----------------------------
RESEED_EVERY_OPS = 100_000     # e.g., reseed DRBG every 100k generate() calls
USE_HYBRID = True              # if False, use pure QRNG for seeds/challenges
REQUIRE_QRNG = False           # if True, raise on QRNG failure (no fallback)
APP_START_TS = time.time()

# -----------------------------
# QRNG client
# -----------------------------
qrng_client = UqrngClient(ip_address="10.1.10.168")

def qrng_bytes(n: int) -> bytes:
    """Fetch n bytes from QRNG; optionally fail hard or fallback to OS CSPRNG."""
    try:
        return qrng_client.GetEntropy(bits_of_entropy=n * 8)
    except Exception as e:
        if REQUIRE_QRNG:
            # Fail hard: upstream caller decides how to handle (e.g., abort request).
            raise RuntimeError(f"QRNG unavailable: {e}")
        print(f"[QRNG WARN] {e} -> using os.urandom fallback")
        return os.urandom(n)

# -----------------------------
# Hybrid DRBG (ChaCha20-based) with mutex
# -----------------------------
class HybridDRBG:
    """
    ChaCha20-based DRBG with periodic QRNG reseed (thread-safe).
    - key: 32 bytes (BLAKE2b of initial seed)
    - nonce: 16-byte little-endian counter per generate()
    - generate(n): returns n bytes of keystream
    - reseed(): mixes in fresh QRNG bytes (or fails if REQUIRE_QRNG=True)
    NOTE: Prototype DRBG; for production use a vetted SP 800-90A DRBG.
    """
    def __init__(self, reseed_every_ops: int = 100_000, initial_from_qrng: bool = True):
        self.reseed_every_ops = max(1, int(reseed_every_ops))
        self.ops = 0
        self.nonce_ctr = 0
        self.reseed_count = 0
        self.last_reseed_ts = None
        self.initial_source = "QRNG" if initial_from_qrng else "OS"
        self._lock = threading.Lock()

        seed = qrng_bytes(32) if initial_from_qrng else os.urandom(32)
        self.key = hashlib.blake2b(seed, digest_size=32).digest()
        print(f"[DRBG] init: source={self.initial_source}; key set")

    def _nonce16_locked(self) -> bytes:
        # Caller holds the lock
        self.nonce_ctr += 1
        return self.nonce_ctr.to_bytes(16, 'little', signed=False)

    def generate(self, n: int) -> bytes:
        with self._lock:
            # Reseed BEFORE generating to keep cadence exact
            if (self.ops % self.reseed_every_ops) == 0 and self.ops > 0:
                self._reseed_locked()

            nonce = self._nonce16_locked()
            cipher = Cipher(algorithms.ChaCha20(self.key, nonce), mode=None)
            out = cipher.encryptor().update(b"\x00" * n)
            self.ops += 1
            return out

    def _reseed_locked(self):
        """Caller holds the lock. May raise if REQUIRE_QRNG=True and device is down."""
        try:
            fresh = qrng_bytes(32)  # may raise RuntimeError if REQUIRE_QRNG=True
        except Exception as e:
            # Surface failure to caller if REQUIRE_QRNG is set
            if REQUIRE_QRNG:
                print(f"[DRBG] reseed FAILED (REQUIRE_QRNG): {e}")
                raise
            # Shouldn't reach here because qrng_bytes already falls back when REQUIRE_QRNG=False,
            # but keep a defensive fallback:
            print(f"[DRBG] reseed WARN: {e} -> fallback to OS")
            fresh = os.urandom(32)

        self.key = hashlib.blake2b(self.key + fresh + self.ops.to_bytes(8, 'big'), digest_size=32).digest()
        self.reseed_count += 1
        self.last_reseed_ts = time.time()
        print(f"[DRBG] reseed #{self.reseed_count} at op={self.ops}")

# Global DRBG instance
drbg = HybridDRBG(reseed_every_ops=RESEED_EVERY_OPS, initial_from_qrng=True)

# -----------------------------
# In-memory user database
# -----------------------------
user_db = {}

# -----------------------------
# Randomness helper (hybrid vs pure QRNG)
# -----------------------------
def rnd_bytes(n: int) -> bytes:
    return drbg.generate(n) if USE_HYBRID else qrng_bytes(n)

# -----------------------------
# Key generation & endpoints
# -----------------------------
def generate_ed25519_key_pair():
    seed = rnd_bytes(32)
    priv = ed25519.Ed25519PrivateKey.from_private_bytes(seed)
    pub  = priv.public_key()
    priv_pem = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_pem = pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    src = "HYBRID/DRBG" if USE_HYBRID else ("QRNG (strict)" if REQUIRE_QRNG else "QRNG")
    print(f"[KEYGEN] Ed25519 seed from {src}")
    return priv_pem, pub_pem

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET','POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']

        # If strict QRNG is required and reseed fails inside DRBG, this will raise
        try:
            private_key_pem, public_key_pem = generate_ed25519_key_pair()
        except Exception as e:
            return f"Registration blocked: {e}", 503

        user_private_key = serialization.load_pem_private_key(private_key_pem, password=None)
        user_public_key  = serialization.load_pem_public_key(public_key_pem)
        user_db[username] = {'private_key': user_private_key, 'public_key': user_public_key}
        session['username'] = username
        print(f"[REGISTER] {username}: passkey created via {'HYBRID' if USE_HYBRID else 'QRNG'}")
        return redirect(url_for('signin'))
    return render_template('register.html')

@app.route('/signin', methods=['GET','POST'])
def signin():
    if request.method == 'POST':
        username = request.form['username']
        if username not in user_db:
            print(f"[ERROR] unknown user '{username}'")
            return "User not found. Please register first."

        # Challenge from DRBG/QRNG
        try:
            challenge = rnd_bytes(16)  # 128-bit
        except Exception as e:
            return f"Sign-in blocked: {e}", 503

        session['challenge'] = challenge
        print(f"[CHALLENGE] {username}: {('HYBRID/DRBG' if USE_HYBRID else 'QRNG')} 128-bit (hex={challenge.hex()})")

        signature = user_db[username]['private_key'].sign(challenge)
        try:
            user_db[username]['public_key'].verify(signature, challenge)
            print("[VERIFY] OK")
            return redirect(url_for('welcome'))
        except Exception:
            print("[VERIFY] FAIL")
            return "Authentication failed. Please try again."
    return render_template('signin.html')

@app.route('/welcome')
def welcome():
    username = session.get('username','Guest')
    return render_template('welcome.html', username=username)

@app.route('/logout')
def logout():
    username = session.get('username','Guest')
    session.clear()
    print(f"[LOGOUT] {username}")
    return redirect(url_for('index'))

# -----------------------------
# Metrics endpoint
# -----------------------------
@app.route('/metrics')
def metrics():
    with drbg._lock:
        now = time.time()
        last_reseed_age = (now - drbg.last_reseed_ts) if drbg.last_reseed_ts else None
        snapshot = {
            "use_hybrid": USE_HYBRID,
            "require_qrng": REQUIRE_QRNG,
            "reseed_every_ops": drbg.reseed_every_ops,
            "ops": drbg.ops,
            "reseed_count": drbg.reseed_count,
            "nonce_counter": drbg.nonce_ctr,
            "initial_source": drbg.initial_source,
            "last_reseed_epoch": drbg.last_reseed_ts,
            "last_reseed_seconds_ago": last_reseed_age,
            "app_uptime_seconds": round(now - APP_START_TS, 3),
        }
    return jsonify(snapshot)

if __name__ == '__main__':
    app.run(debug=True)
