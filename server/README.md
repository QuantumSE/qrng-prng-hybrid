
# Flask Backend (Optional)

This folder contains a Flask app that demonstrates the **QRNG↔DRBG hybrid** backend described in the site.
It serves the uploaded templates (`index.html`, `register.html`, `signin.html`, `welcome.html`) and exposes `/metrics`.

## Quick start

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install flask cryptography uqrng_direct
export FLASK_APP=app.py
python app.py
# then visit http://127.0.0.1:5000/
```

### Notes
- The app expects a QRNG at `10.1.10.168` via `uqrng_direct`. If unavailable:
  - Set `REQUIRE_QRNG = False` inside `app.py` to allow fallback to `os.urandom`.
  - Leave `USE_HYBRID = True` to exercise the **HybridDRBG** reseeding logic.
- The static background image is referenced as `/static/SE%26M%20Logo.jpg` in templates,
  which maps to the file `server/static/SE&M Logo.jpg`.
- For production use, replace the prototype DRBG with a vetted **SP 800-90A HMAC-DRBG / CTR-DRBG**.
