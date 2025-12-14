from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature

INPUT_FILE = "message.txt"
SIGNATURE_FILE = "signature.bin"
PUBLIC_KEY_FILE = "public_key.pem"

# читаем сообщение
with open(INPUT_FILE, "rb") as f:
    data = f.read()

# читаем подпись
with open(SIGNATURE_FILE, "rb") as f:
    signature = f.read()

# загружаем публичный ключ
with open(PUBLIC_KEY_FILE, "rb") as f:
    public_key = serialization.load_pem_public_key(f.read())

# проверяем подпись
try:
    public_key.verify(
        signature,
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    print("SIGNATURE VALID")
except InvalidSignature:
    print("SIGNATURE INVALID")
