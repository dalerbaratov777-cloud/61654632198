from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

INPUT_FILE = "message.txt"
PRIVATE_KEY_FILE = "private_key.pem"
SIGNATURE_FILE = "signature.bin"

# читаем сообщение
with open(INPUT_FILE, "rb") as f:
    data = f.read()

# загружаем приватный ключ
with open(PRIVATE_KEY_FILE, "rb") as f:
    private_key = serialization.load_pem_private_key(
        f.read(),
        password=None
    )

# создаём подпись (RSA + SHA256)
signature = private_key.sign(
    data,
    padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH
    ),
    hashes.SHA256()
)

# сохраняем подпись
with open(SIGNATURE_FILE, "wb") as f:
    f.write(signature)

print("SIGN OK")
