#!/usr/bin/env python3
"""Chiffre le tableau de bord Studio Ginko pour une publication web protégée par mot de passe.

Usage : python3 encrypt_dashboard.py <source.html> <sortie/index.html>
        (mot de passe : variable GINKO_DASH_PASSWORD ; sel fixe en base64 : GINKO_DASH_SALT)

Chiffrement : PBKDF2-SHA256 (600 000 itérations, sel aléatoire 16 o) -> clé AES-256,
AES-GCM (IV aléatoire 12 o). Déchiffrement dans le navigateur via WebCrypto.
Le fichier publié ne contient aucune donnée lisible sans le mot de passe.
"""
import base64, json, os, sys
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

ITER = 600_000

def main(src, dst):
    pwd = os.environ.get("GINKO_DASH_PASSWORD")
    if not pwd:
        sys.exit("GINKO_DASH_PASSWORD manquant")
    html = open(src, encoding="utf-8").read()
    # La source publiée sur claude.ai n'a pas de doctype : on rend un document complet.
    if "<!doctype" not in html[:200].lower():
        html = ('<!DOCTYPE html>\n<html lang="fr"><head><meta charset="utf-8">'
                '<meta name="viewport" content="width=device-width, initial-scale=1"></head><body>\n'
                + html + "\n</body></html>")
    # Sel fixe (GINKO_DASH_SALT, base64) : la clé reste la même d'une semaine à l'autre, ce qui
    # permet au navigateur de mémoriser la clé dérivée (jamais le mot de passe).
    salt = base64.b64decode(os.environ["GINKO_DASH_SALT"])
    iv = os.urandom(12)
    key = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=ITER).derive(pwd.encode())
    ct = AESGCM(key).encrypt(iv, html.encode("utf-8"), None)
    payload = json.dumps({"s": base64.b64encode(salt).decode(), "i": base64.b64encode(iv).decode(),
                          "n": ITER, "c": base64.b64encode(ct).decode()})
    page = TEMPLATE.replace("__PAYLOAD__", payload)
    os.makedirs(os.path.dirname(dst) or ".", exist_ok=True)
    open(dst, "w", encoding="utf-8").write(page)
    print(f"OK {dst} — {len(page)} octets")

TEMPLATE = r"""<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<title>Tableau de bord Studio Ginko</title>
<style>
  :root{--bg:#f3f2ee;--card:#ffffff;--ink:#1f2a24;--muted:#5b6660;--accent:#2f5d46;--err:#b3372f;}
  *{box-sizing:border-box}
  body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;
       background:var(--bg);color:var(--ink);font-family:"Segoe UI",Helvetica,Arial,sans-serif;padding:16px}
  form{background:var(--card);width:100%;max-width:360px;padding:28px 24px;border-radius:10px;
       box-shadow:0 1px 3px rgba(0,0,0,.08);display:flex;flex-direction:column;gap:14px}
  h1{margin:0;font-size:1.15rem}
  p{margin:0;color:var(--muted);font-size:.88rem}
  label{font-size:.82rem;font-weight:600}
  input[type=password]{width:100%;padding:11px 12px;font-size:1rem;border:1px solid #c9ccc5;border-radius:6px}
  input[type=password]:focus{outline:2px solid var(--accent);border-color:var(--accent)}
  .row{display:flex;align-items:center;gap:8px;font-size:.85rem}
  button{padding:11px;font-size:1rem;font-weight:600;color:#fff;background:var(--accent);border:0;border-radius:6px;cursor:pointer}
  button:disabled{opacity:.6}
  #msg{color:var(--err);font-size:.85rem;min-height:1.1em}
</style>
</head>
<body>
<form id="f" autocomplete="on">
  <h1>Studio Ginko — Tableau de bord</h1>
  <p>Accès réservé aux associés.</p>
  <input type="text" name="username" value="studio-ginko" autocomplete="username" hidden>
  <div>
    <label for="pw">Mot de passe</label>
    <input id="pw" name="password" type="password" autocomplete="current-password" required autofocus>
  </div>
  <label class="row"><input id="rem" type="checkbox" checked> Se souvenir sur cet appareil</label>
  <button id="go" type="submit">Ouvrir</button>
  <div id="msg" role="alert"></div>
</form>
<script>
const P = __PAYLOAD__;
const KEY_STORE = "ginko-dash-key";
const b64 = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));
async function deriveRaw(pw){
  const base = await crypto.subtle.importKey("raw", new TextEncoder().encode(pw), "PBKDF2", false, ["deriveBits"]);
  return new Uint8Array(await crypto.subtle.deriveBits({name:"PBKDF2", hash:"SHA-256", salt:b64(P.s), iterations:P.n}, base, 256));
}
async function decryptWith(raw){
  const key = await crypto.subtle.importKey("raw", raw, "AES-GCM", false, ["decrypt"]);
  const plain = await crypto.subtle.decrypt({name:"AES-GCM", iv:b64(P.i)}, key, b64(P.c));
  return new TextDecoder().decode(plain);
}
// Remplacer la page n'est fiable qu'une fois l'écran de connexion entièrement chargé : appelé plus tôt
// (réouverture avec clé mémorisée), document.open() est ignoré et le tableau de bord hérite des styles
// de l'écran de connexion (contenu centré, débordement latéral sur téléphone).
function show(html){
  const go = () => { document.open(); document.write(html); document.close(); };
  if(document.readyState === "complete") go(); else window.addEventListener("load", go, {once:true});
}
// « Se souvenir » : le navigateur garde la clé dérivée (jamais le mot de passe). Le sel étant fixe, elle
// reste valable d'une publication à l'autre ; si le mot de passe change, elle est rejetée et effacée.
(async () => {
  try{
    const saved = localStorage.getItem(KEY_STORE);
    if(saved){ show(await decryptWith(b64(saved))); }
  }catch(e){ try{ localStorage.removeItem(KEY_STORE); }catch(_){} }
})();
document.getElementById("f").addEventListener("submit", async ev => {
  ev.preventDefault();
  const pw = document.getElementById("pw").value, btn = document.getElementById("go"), msg = document.getElementById("msg");
  btn.disabled = true; msg.textContent = ""; btn.textContent = "Ouverture…";
  try{
    const raw = await deriveRaw(pw);
    const html = await decryptWith(raw);
    if(document.getElementById("rem").checked){ try{ localStorage.setItem(KEY_STORE, btoa(String.fromCharCode(...raw))); }catch(_){} }
    show(html);
  }catch(e){
    msg.textContent = "Mot de passe incorrect."; btn.disabled = false; btn.textContent = "Ouvrir";
  }
});
</script>
</body>
</html>
"""

if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
