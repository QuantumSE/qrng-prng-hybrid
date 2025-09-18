# server/app.py
from flask import Flask, render_template, request, redirect, url_for, session, jsonify
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
import os, time, hashlib, threading, logging

# -----------------------------
# Optional QRNG (lazy import)
# -----------------------------
try:
    from uqrng_direct.client import UqrngClient  # may pull in gRPC deps
    HAVE_QRNG = True
except Exception as e:
    HAVE_QRNG = False
    print(f"[QRNG IMPORT WARN] {e} -> QRNG disabled (fallback to os.urandom)")

# -----------------------------
# App / Config
# -----------------------------
app = Flask(__name__)

# SECRET_KEY for sessions (use env in prod)
app.secret_key = os.environ.get("FLASK_SECRET_KEY") or os.urandom(24)

# Tunables (can override via env)
RESEED_EVERY_OPS = int(os.environ.get("RESEED_EVERY_OPS", "100000"))  # reseed DRBG every N generate() calls
USE_HYBRID = os.environ.get("USE_HYBRID", "true").lower() == "true"   # False -> pure QRNG for bytes
REQUIRE_QRNG = os.environ.get("REQUIRE_QRNG", "false").lower() == "true"
QRNG_IP = os.environ.get("QRNG_IP", "10.1.10.168")
APP_START_TS = time.time()

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("qrng-hybrid")

# -----------------------------
# QRNG client (if available)
# -----------------------------
qrng_client = UqrngClient(ip_address=QRNG_IP) if HAVE_QRNG else None

def qrng_bytes(n: int) -> bytes:
    """
    Fetch n bytes from QRNG; fall back to OS CSPRNG unless REQUIRE_QRNG=True.
    """
    if not HAVE_QRNG or qrng_client is None:
        if REQUIRE_QRNG:
            raise RuntimeError("QRNG required but uqrng_direct not available")
        return os.urandom(n)
    try:
        return qrng_client.GetEntropy(bits_of_entropy=n * 8)
    except Exception as e:
        if REQUIRE_QRNG:
            raise RuntimeError(f"QRNG unavailable: {e}")
        log.warning("[QRNG WARN] %s -> using os.urandom fallback", e)
        return os.urandom(n)

# -----------------------------
# Hybrid DRBG (ChaCha20-based)
# -----------------------------
class HybridDRBG:
    """
    ChaCha20-based DRBG with periodic QRNG reseed (thread-safe).
    - key: 32 bytes (BLAKE2b of initial seed)
    - nonce: 16-byte little-endian counter per generate()
    - generate(n): returns n bytes of keystream
    - reseed(): mixes in fresh QRNG bytes
    NOTE: Prototype; for production use a vetted NIST SP 800-90A DRBG.
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
        log.info("[DRBG] init: source=%s; key ready", self.initial_source)

    def _nonce16_locked(self) -> bytes:
        # Caller holds the lock
        self.nonce_ctr += 1
        return self.nonce_ctr.to_bytes(16, "little", signed=False)

    def generate(self, n: int) -> bytes:
        with self._lock:
            if (self.ops % self.reseed_every_ops) == 0 and self.ops > 0:
                self._reseed_locked()

            nonce = self._nonce16_locked()
            cipher = Cipher(algorithms.ChaCha20(self.key, nonce), mode=None)
            out = cipher.encryptor().update(b"\x00" * n)
            self.ops += 1
            return out

    def _reseed_locked(self):
        try:
            fresh = qrng_bytes(32)  # may raise if REQUIRE_QRNG=True and QRNG down
        except Exception as e:
            # Shouldn't occur with REQUIRE_QRNG=False because qrng_bytes falls back,
            # but keep defensive fallback anyway:
            log.warning("[DRBG] reseed WARN: %s -> fallback to OS", e)
            fresh = os.urandom(32)

        self.key = hashlib.blake2b(self.key + fresh + self.ops.to_bytes(8, "big"), digest_size=32).digest()
        self.reseed_count += 1
        self.last_reseed_ts = time.time()
        log.info("[DRBG] reseed #%d at op=%d", self.reseed_count, self.ops)

# Global DRBG instance (seed from QRNG if we have it)
drbg = HybridDRBG(reseed_every_ops=RESEED_EVERY_OPS, initial_from_qrng=HAVE_QRNG)

def rnd_bytes(n: int) -> bytes:
    return drbg.generate(n) if USE_HYBRID else qrng_bytes(n)

# -----------------------------
# In-memory "users"
# -----------------------------
user_db = {}

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
    log.info("[KEYGEN] Ed25519 seed from %s", src)
    return priv_pem, pub_pem

# -----------------------------
# Routes
# -----------------------------
@app.route("/")
def index():
    return render_template("index.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        if not username:
            return "Username required", 400

        try:
            private_key_pem, public_key_pem = generate_ed25519_key_pair()
        except Exception as e:
            return f"Registration blocked: {e}", 503

        user_private_key = serialization.load_pem_private_key(private_key_pem, password=None)
        user_public_key  = serialization.load_pem_public_key(public_key_pem)
        user_db[username] = {"private_key": user_private_key, "public_key": user_public_key}
        session["username"] = username
        log.info("[REGISTER] %s: passkey via %s", username, "HYBRID" if USE_HYBRID else "QRNG")
        return redirect(url_for("signin"))
    return render_template("register.html")

@app.route("/signin", methods=["GET", "POST"])
def signin():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        if username not in user_db:
            log.error("[AUTH] unknown user '%s'", username)
            return "User not found. Please register first.", 404

        try:
            challenge = rnd_bytes(16)  # 128-bit
        except Exception as e:
            return f"Sign-in blocked: {e}", 503

        session["challenge"] = challenge
        log.info("[CHALLENGE] %s: %s 128-bit (hex=%s)",
                 username, ("HYBRID/DRBG" if USE_HYBRID else "QRNG"), challenge.hex())

        signature = user_db[username]["private_key"].sign(challenge)
        try:
            user_db[username]["public_key"].verify(signature, challenge)
            log.info("[VERIFY] OK for %s", username)
            session["username"] = username
            return redirect(url_for("welcome"))
        except Exception:
            log.error("[VERIFY] FAIL for %s", username)
            return "Authentication failed. Please try again.", 401
    return render_template("signin.html")

@app.route("/welcome")
def welcome():
    username = session.get("username", "Guest")
    return render_template("welcome.html", username=username)

@app.route("/logout")
def logout():
    username = session.get("username", "Guest")
    session.clear()
    log.info("[LOGOUT] %s", username)
    return redirect(url_for("index"))

@app.route("/metrics")
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
            "have_qrng_module": HAVE_QRNG,
        }
    return jsonify(snapshot)

@app.route("/healthz")
def healthz():
    return "ok", 200

# -----------------------------
# Entrypoint
# -----------------------------
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    debug = os.environ.get("FLASK_DEBUG", "false").lower() == "true"
    app.run(host="0.0.0.0", port=port, debug=debug)
