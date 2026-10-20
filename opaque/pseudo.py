import hmac, hashlib, os, random, re, secrets, string, sqlite3
from faker import Faker
from opaque.keywords import KEYWORDS
from opaque.test_set import TEST_SET

WORDS = sorted({k.lower() for k in KEYWORDS}, key=lambda w: (-len(w), w))
KEY_PATH = 'vault.key'
faker = Faker()

# use local secret key to get the fakes, creted once and owner only
def load_key(path = KEY_PATH):
    if not os.path.exists(path):
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'wb') as f:
            f.write(secrets.token_bytes(32))
    with open(path, 'rb') as f:
        return f.read()

def make_rng(real, key, attempt=0):
    digest = hmac.new(key, f'{attempt}:{real}'.encode(), hashlib.sha256).digest()
    return random.Random(digest)

def randomize(text, rng):
    out = ""
    for ch in text:
        if ch.isdigit():
            out += rng.choice(string.digits)
        elif ch.isupper():
            out += rng.choice(string.ascii_uppercase)
        elif ch.islower():
            out += rng.choice(string.ascii_lowercase)
        else:
            out += ch          # keep symbols like - and _
    return out

# the rng is seed from HMAC (hash based message authentication code) of the secret so same secret always give same fake
def create_fake_secret(secret, rng):
    lower = secret.lower()

    for word in WORDS:
        i = lower.find(word)
        if i != -1:
            j = i + len(word)
            return randomize(secret[:i], rng) + secret[i:j] + randomize(secret[j:], rng)
    return randomize(secret, rng)


def _seed_faker(rng):
    faker.seed_instance(rng.getrandbits(64))   # seeded from the HMAC -> stable names

def fake_person(real, rng):
    _seed_faker(rng); return faker.name()

def fake_location(real, rng):
    _seed_faker(rng); return faker.city()

def fake_email(real, rng):
    _seed_faker(rng); return faker.safe_email()   # example.* domain, so the real employer domain doesn't leak

def fake_card(real, rng):
    s = randomize(real, rng)
    digits = [c for c in s if c.isdigit()]
    # Luhn: double every second digit starting from the rightmost body digit
    total = 0
    for i, d in enumerate(reversed(digits[:-1])):
        d = int(d)
        total += (d * 2 - 9 if d * 2 > 9 else d * 2) if i % 2 == 0 else d
    digits[-1] = str((10 - total % 10) % 10)
    it = iter(digits)
    return "".join(next(it) if c.isdigit() else c for c in s)

def fake_iban(real, rng):
    clean = real.replace(" ", "")
    cc, bban = clean[:2], randomize(clean[4:], rng)
    num = "".join(str(int(c, 36)) for c in bban + cc + "00")
    new = cc + f"{98 - int(num) % 97:02d}" + bban   # recompute the check digits
    return " ".join(new[i:i + 4] for i in range(0, len(new), 4)) if " " in real else new

def fake_ip(real, rng):
    if ":" in real:
        return "2001:db8::" + format(rng.randint(1, 0xffff), "x")
    return rng.choice(["192.0.2.", "198.51.100.", "203.0.113."]) + str(rng.randint(1, 254))

PII_GENERATORS = {
    "PERSON": fake_person, "LOCATION": fake_location, "EMAIL_ADDRESS": fake_email,
    "CREDIT_CARD": fake_card, "IBAN_CODE": fake_iban, "IP_ADDRESS": fake_ip,
    # everything else below keeps the format like digits->digits, letters->letters
    **{e: randomize for e in ("PHONE_NUMBER", "US_SSN", "US_ITIN", "US_PASSPORT",
                              "US_DRIVER_LICENSE", "US_BANK_NUMBER", "UK_NHS",
                              "MEDICAL_LICENSE", "MAC_ADDRESS")},
}

# ihandle pii and secret
def create_fake(real, entity_type, tier, key, attempt=0):
    rng = make_rng(real, key, attempt)
    gen = PII_GENERATORS.get(entity_type)
    if gen:
        return gen(real, rng)
    if tier is not None and tier != "SECRET":
        return randomize(real, rng)
    return create_fake_secret(real, rng)

# basically handle the sqlite
class Vault:
    # create workspace and db
    def __init__(self, path='vault.db', workspace='default', key_path=KEY_PATH):
        self.workspace = workspace
        self.key = load_key(key_path)
        self.db = sqlite3.connect(path)
        self.db.execute('''CREATE TABLE IF NOT EXISTS mapping (workspace TEXT, fake TEXT, real TEXT, PRIMARY KEY (workspace, fake))''')

    # retry if the fake is the same as real secret or if it already exist, well only likely for short secrets (really small chance but whatever)
    def surrogate(self, real, entity_type=None, tier=None):
        for attempt in range(20):
            fake = create_fake(real, entity_type, tier, self.key, attempt)
            row = self.db.execute('SELECT real FROM mapping WHERE workspace=? AND fake=?', (self.workspace, fake)).fetchone()
            if row and row[0] == real:
                return fake
            if fake != real and not row:
                self.db.execute('INSERT INTO mapping VALUES (?, ?, ?)', (self.workspace, fake, real))
                self.db.commit()
                return fake
        raise ValueError('could not generate unique surrogate')

    
    # adjust to the Findings object with offset so not strings, replace from end keep earlier offset make sense
    def sanitize(self, text, findings):
        spans = {(f.start, f.end): f for f in findings}
        for f in sorted(findings, key=lambda f: -len(f.text)):   # longest first
            pat = re.escape(f.text) if f.tier == "SECRET" else rf'(?<!\w){re.escape(f.text)}(?!\w)'
            for m in re.finditer(pat, text):
                s, e = m.span()
                if all(e <= a or s >= b for a, b in spans):       # skip overlaps
                    spans[(s, e)] = f
        for (s, e), f in sorted(spans.items(), reverse=True):     # right to left
            text = text[:s] + self.surrogate(f.text, f.entity_type, f.tier) + text[e:]
        return text

    # this is after the external llm return the response
    def restore(self, text):
        rows = self.db.execute('SELECT fake, real FROM mapping WHERE workspace=?', (self.workspace,)).fetchall()
        if not rows:
            return text
        m = dict(rows)
        pat = re.compile('|'.join(map(re.escape, sorted(m, key=len, reverse=True))))
        return pat.sub(lambda x: m[x.group()], text)

if __name__ == '__main__':
    vault = Vault(":memory:")
    for secret in TEST_SET:
        fake = vault.surrogate(secret)
        print(f'{secret} : {fake}')
        assert vault.restore(fake) == secret
        assert vault.surrogate(secret) == fake

    for real, ent, tier in [("john.smith@acme.com", "EMAIL_ADDRESS", "PII_MODERATE"),
                        ("4111 1111 1111 1111", "CREDIT_CARD", "PII_HIGH"),
                        ("GB82 WEST 1234 5698 7654 32", "IBAN_CODE", "PII_HIGH"),
                        ("+1 415-555-0132", "PHONE_NUMBER", "PII_MODERATE"),
                        ("10.1.2.3", "IP_ADDRESS", "PII_LOW"),
                        ("Priya Sharma", "PERSON", "PII_MODERATE")]:
        fake = vault.surrogate(real, ent, tier)
        print(f'{real} : {fake}')
        assert vault.restore(fake) == real