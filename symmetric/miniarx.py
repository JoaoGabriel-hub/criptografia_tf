"""
miniarx.py

Implementação do MiniARX-64 — cifra de bloco ARX (Addition-Rotation-XOR)
original, projetada para este trabalho.

─────────────────────────────────────────────────────────────────────
ESPECIFICAÇÃO
─────────────────────────────────────────────────────────────────────
    Tamanho de bloco : 64 bits (2 words de 32 bits)
    Tamanho de chave : 128 bits
    Número de rodadas: 16
    Operações        : adição mod 2^32, rotação, XOR (ARX puro)
    Modo de operação : ECB (blocos independentes), CBC disponível

─────────────────────────────────────────────────────────────────────
FUNÇÃO DE RODADA (cifração)
─────────────────────────────────────────────────────────────────────
    Entrada : (A, B) — dois words de 32 bits
    Subchave: (K_A, K_B) da rodada atual

    A = A + B          (mod 2^32)   — mistura não-linear
    A = rotl(A, ROT_A)             — difusão intra-word
    A = A XOR K_A                  — confusão com subchave

    B = B + A          (mod 2^32)   — mistura cruzada (A já atualizado)
    B = rotl(B, ROT_B)             — difusão intra-word
    B = B XOR K_B                  — confusão com subchave

    Saída: (A, B) atualizados

─────────────────────────────────────────────────────────────────────
FUNÇÃO DE RODADA INVERSA (decifração)
─────────────────────────────────────────────────────────────────────
    Todas as operações são invertíveis:
        XOR   → XOR (própria inversa)
        rotl  → rotr
        adição → subtração mod 2^32

    B = B XOR K_B
    B = rotr(B, ROT_B)
    B = B - A          (mod 2^32)

    A = A XOR K_A
    A = rotr(A, ROT_A)
    A = A - B          (mod 2^32)   — B já restaurado

─────────────────────────────────────────────────────────────────────
CONSTANTES DE ROTAÇÃO
─────────────────────────────────────────────────────────────────────
    ROT_A = 12, ROT_B = 7

    Escolhidas por maximizar o número de bits afetados após 2 rodadas
    (critério de difusão). A combinação (12, 7) é estudada na literatura
    ARX e usada pelo SPECK-32 da NSA.

─────────────────────────────────────────────────────────────────────
MODO CBC
─────────────────────────────────────────────────────────────────────
    Para mensagens com múltiplos blocos, o modo CBC (Cipher Block
    Chaining) é disponibilizado: cada bloco de plaintext é XORado com
    o criptograma do bloco anterior antes de cifrar, propagando
    dependências entre blocos e prevenindo padrões repetidos.
"""

import os
import struct

from symmetric.key_schedule import (
    generate_subkeys,
    WORD_BITS,
    WORD_MOD,
    NUM_ROUNDS,
)

# ─────────────────────────────────────────────────────────────────────
# Constantes de rotação
# ─────────────────────────────────────────────────────────────────────

ROT_A = 12   # rotação aplicada ao word A a cada rodada
ROT_B = 7    # rotação aplicada ao word B a cada rodada

BLOCK_SIZE = 8   # bytes (64 bits)
KEY_SIZE   = 16  # bytes (128 bits)


# ─────────────────────────────────────────────────────────────────────
# Primitivos ARX de 32 bits
# ─────────────────────────────────────────────────────────────────────

def _rotl32(x: int, n: int) -> int:
    """Rotação circular à esquerda de x (32 bits) por n posições."""
    n = n % WORD_BITS
    return ((x << n) | (x >> (WORD_BITS - n))) & 0xFFFFFFFF


def _rotr32(x: int, n: int) -> int:
    """Rotação circular à direita de x (32 bits) por n posições."""
    n = n % WORD_BITS
    return ((x >> n) | (x << (WORD_BITS - n))) & 0xFFFFFFFF


def _add32(a: int, b: int) -> int:
    """Adição modular de 32 bits."""
    return (a + b) & 0xFFFFFFFF


def _sub32(a: int, b: int) -> int:
    """Subtração modular de 32 bits (inversa da adição)."""
    return (a - b) & 0xFFFFFFFF


# ─────────────────────────────────────────────────────────────────────
# Função de rodada
# ─────────────────────────────────────────────────────────────────────

def _round_encrypt(A: int, B: int, K_A: int, K_B: int):
    """
    Uma rodada de cifração do MiniARX-64.

    Operações em ordem:
        1. A = (A + B) mod 2^32
        2. A = rotl(A, ROT_A)
        3. A = A XOR K_A
        4. B = (B + A) mod 2^32   [A já atualizado]
        5. B = rotl(B, ROT_B)
        6. B = B XOR K_B

    Retorna: (A, B) atualizados
    """
    A = _add32(A, B)
    A = _rotl32(A, ROT_A)
    A = A ^ K_A

    B = _add32(B, A)
    B = _rotl32(B, ROT_B)
    B = B ^ K_B

    return A, B


def _round_decrypt(A: int, B: int, K_A: int, K_B: int):
    """
    Uma rodada de decifração do MiniARX-64 (inversa de _round_encrypt).

    Operações em ordem inversa:
        1. B = B XOR K_B
        2. B = rotr(B, ROT_B)
        3. B = (B - A) mod 2^32   [A ainda não restaurado]
        4. A = A XOR K_A
        5. A = rotr(A, ROT_A)
        6. A = (A - B) mod 2^32   [B já restaurado]

    Retorna: (A, B) restaurados
    """
    B = B ^ K_B
    B = _rotr32(B, ROT_B)
    B = _sub32(B, A)

    A = A ^ K_A
    A = _rotr32(A, ROT_A)
    A = _sub32(A, B)

    return A, B


# ─────────────────────────────────────────────────────────────────────
# Cifração / Decifração de um bloco (64 bits)
# ─────────────────────────────────────────────────────────────────────

def encrypt_block(plaintext_block: bytes, subkeys: list) -> bytes:
    """
    Cifra um bloco de 8 bytes (64 bits) com o MiniARX-64.

    Parâmetros:
        plaintext_block: exatamente 8 bytes de plaintext
        subkeys: lista de 16 tuplas (K_A, K_B) gerada por generate_subkeys()

    Retorna:
        8 bytes de ciphertext
    """
    if len(plaintext_block) != BLOCK_SIZE:
        raise ValueError(f"Bloco deve ter {BLOCK_SIZE} bytes, recebeu {len(plaintext_block)}")

    # Interpreta os 8 bytes como dois words de 32 bits (big-endian)
    A, B = struct.unpack(">II", plaintext_block)

    # 16 rodadas de cifração
    for K_A, K_B in subkeys:
        A, B = _round_encrypt(A, B, K_A, K_B)

    return struct.pack(">II", A, B)


def decrypt_block(ciphertext_block: bytes, subkeys: list) -> bytes:
    """
    Decifra um bloco de 8 bytes (64 bits) com o MiniARX-64.

    Parâmetros:
        ciphertext_block: exatamente 8 bytes de ciphertext
        subkeys: a MESMA lista gerada por generate_subkeys() usada na cifração

    Retorna:
        8 bytes de plaintext original
    """
    if len(ciphertext_block) != BLOCK_SIZE:
        raise ValueError(f"Bloco deve ter {BLOCK_SIZE} bytes, recebeu {len(ciphertext_block)}")

    A, B = struct.unpack(">II", ciphertext_block)

    # Rodadas em ordem reversa com subchaves invertidas
    for K_A, K_B in reversed(subkeys):
        A, B = _round_decrypt(A, B, K_A, K_B)

    return struct.pack(">II", A, B)


# ─────────────────────────────────────────────────────────────────────
# Classe principal — interface de alto nível
# ─────────────────────────────────────────────────────────────────────

class MiniARX64:
    """
    Interface de alto nível para o MiniARX-64.

    Suporta cifração/decifração de mensagens de tamanho arbitrário
    em modo ECB ou CBC (com padding PKCS#7).

    Uso:
        cipher = MiniARX64(key_bytes)
        ct = cipher.encrypt(plaintext, mode='cbc')
        pt = cipher.decrypt(ct, mode='cbc')
    """

    BLOCK_SIZE = BLOCK_SIZE
    KEY_SIZE   = KEY_SIZE

    def __init__(self, key: bytes):
        """
        Parâmetros:
            key: 16 bytes (128 bits) de chave mestre
        """
        if len(key) != KEY_SIZE:
            raise ValueError(f"Chave deve ter {KEY_SIZE} bytes (128 bits)")
        self.key = key
        self.subkeys = generate_subkeys(key)

    # ── Padding PKCS#7 ───────────────────────────────────────────────

    @staticmethod
    def _pad(data: bytes) -> bytes:
        """Aplica padding PKCS#7 para completar múltiplo de BLOCK_SIZE."""
        pad_len = BLOCK_SIZE - (len(data) % BLOCK_SIZE)
        return data + bytes([pad_len] * pad_len)

    @staticmethod
    def _unpad(data: bytes) -> bytes:
        """Remove padding PKCS#7."""
        pad_len = data[-1]
        if pad_len < 1 or pad_len > BLOCK_SIZE:
            raise ValueError("Padding inválido")
        if data[-pad_len:] != bytes([pad_len] * pad_len):
            raise ValueError("Padding corrompido")
        return data[:-pad_len]

    # ── Modo ECB ─────────────────────────────────────────────────────

    def encrypt_ecb(self, plaintext: bytes) -> bytes:
        """Cifra em modo ECB (blocos independentes, com padding PKCS#7)."""
        padded = self._pad(plaintext)
        ct = b""
        for i in range(0, len(padded), BLOCK_SIZE):
            ct += encrypt_block(padded[i:i+BLOCK_SIZE], self.subkeys)
        return ct

    def decrypt_ecb(self, ciphertext: bytes) -> bytes:
        """Decifra em modo ECB."""
        if len(ciphertext) % BLOCK_SIZE != 0:
            raise ValueError("Ciphertext deve ser múltiplo do tamanho de bloco")
        pt = b""
        for i in range(0, len(ciphertext), BLOCK_SIZE):
            pt += decrypt_block(ciphertext[i:i+BLOCK_SIZE], self.subkeys)
        return self._unpad(pt)

    # ── Modo CBC ─────────────────────────────────────────────────────

    def encrypt_cbc(self, plaintext: bytes, iv: bytes = None) -> bytes:
        """
        Cifra em modo CBC (Cipher Block Chaining).

        Parâmetros:
            plaintext: mensagem de qualquer tamanho
            iv: vetor de inicialização de 8 bytes (gerado aleatoriamente
                se não fornecido)

        Retorna:
            iv (8 bytes) + ciphertext
        """
        if iv is None:
            iv = os.urandom(BLOCK_SIZE)
        if len(iv) != BLOCK_SIZE:
            raise ValueError(f"IV deve ter {BLOCK_SIZE} bytes")

        padded = self._pad(plaintext)
        ct = iv
        prev = iv

        for i in range(0, len(padded), BLOCK_SIZE):
            block = padded[i:i+BLOCK_SIZE]
            # XOR do bloco atual com o ciphertext anterior (ou IV)
            xored = bytes(a ^ b for a, b in zip(block, prev))
            enc = encrypt_block(xored, self.subkeys)
            ct += enc
            prev = enc

        return ct

    def decrypt_cbc(self, ciphertext: bytes) -> bytes:
        """
        Decifra em modo CBC.

        Parâmetros:
            ciphertext: iv (primeiros 8 bytes) + blocos cifrados
        """
        if len(ciphertext) < BLOCK_SIZE * 2 or len(ciphertext) % BLOCK_SIZE != 0:
            raise ValueError("Ciphertext CBC inválido")

        iv   = ciphertext[:BLOCK_SIZE]
        data = ciphertext[BLOCK_SIZE:]
        pt   = b""
        prev = iv

        for i in range(0, len(data), BLOCK_SIZE):
            block = data[i:i+BLOCK_SIZE]
            dec = decrypt_block(block, self.subkeys)
            pt += bytes(a ^ b for a, b in zip(dec, prev))
            prev = block

        return self._unpad(pt)

    # ── Interface unificada ───────────────────────────────────────────

    def encrypt(self, plaintext: bytes, mode: str = 'cbc', iv: bytes = None) -> bytes:
        """Cifra em modo ECB ou CBC."""
        if mode == 'ecb':
            return self.encrypt_ecb(plaintext)
        elif mode == 'cbc':
            return self.encrypt_cbc(plaintext, iv)
        raise ValueError(f"Modo desconhecido: {mode}. Use 'ecb' ou 'cbc'.")

    def decrypt(self, ciphertext: bytes, mode: str = 'cbc') -> bytes:
        """Decifra em modo ECB ou CBC."""
        if mode == 'ecb':
            return self.decrypt_ecb(ciphertext)
        elif mode == 'cbc':
            return self.decrypt_cbc(ciphertext)
        raise ValueError(f"Modo desconhecido: {mode}. Use 'ecb' ou 'cbc'.")


# ─────────────────────────────────────────────────────────────────────
# Testes de sanidade
# ─────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import os

    print("=== Teste: cifração/decifração de bloco único ===")
    key   = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    block = bytes.fromhex("0011223344556677")

    from symmetric.key_schedule import generate_subkeys
    subkeys = generate_subkeys(key)

    ct = encrypt_block(block, subkeys)
    pt = decrypt_block(ct, subkeys)

    print(f"Plaintext : {block.hex()}")
    print(f"Ciphertext: {ct.hex()}")
    print(f"Decifrado : {pt.hex()}")
    assert pt == block
    print("Decifração correta.  OK")

    print("\n=== Teste: ciphertext diferente do plaintext ===")
    assert ct != block
    print(f"Plaintext != Ciphertext: {block.hex()} != {ct.hex()}  OK")

    print("\n=== Teste: chaves diferentes produzem ciphertexts diferentes ===")
    key2 = bytes.fromhex("ff0102030405060708090a0b0c0d0e0f")
    ct2  = encrypt_block(block, generate_subkeys(key2))
    assert ct != ct2
    print(f"Chave 1: {ct.hex()}")
    print(f"Chave 2: {ct2.hex()}")
    print("OK")

    print("\n=== Teste: MiniARX64 — modo ECB com padding ===")
    cipher = MiniARX64(key)
    msg = b"Criptografia simetrica original"
    ct_ecb = cipher.encrypt(msg, mode='ecb')
    pt_ecb = cipher.decrypt(ct_ecb, mode='ecb')
    assert pt_ecb == msg
    print(f"Mensagem  : {msg}")
    print(f"Decifrado : {pt_ecb}")
    print("ECB OK")

    print("\n=== Teste: MiniARX64 — modo CBC com IV aleatório ===")
    ct_cbc = cipher.encrypt(msg, mode='cbc')
    pt_cbc = cipher.decrypt(ct_cbc, mode='cbc')
    assert pt_cbc == msg
    print(f"Mensagem  : {msg}")
    print(f"Decifrado : {pt_cbc}")
    print("CBC OK")

    print("\n=== Teste: CBC com IV fixo é determinístico ===")
    iv = bytes(8)
    ct1 = cipher.encrypt_cbc(msg, iv=iv)
    ct2 = cipher.encrypt_cbc(msg, iv=iv)
    assert ct1 == ct2
    print("Mesmo IV → mesmo ciphertext.  OK")

    print("\n=== Teste: CBC com IV aleatório é não-determinístico ===")
    ct_a = cipher.encrypt_cbc(msg)
    ct_b = cipher.encrypt_cbc(msg)
    assert ct_a != ct_b
    print("IVs diferentes → ciphertexts diferentes.  OK")

    print("\n=== Teste: 1 bit diferente no plaintext → ciphertext totalmente diferente ===")
    block_a = bytes.fromhex("0000000000000000")
    block_b = bytes.fromhex("0000000000000001")  # apenas 1 bit diferente
    ct_a = encrypt_block(block_a, subkeys)
    ct_b = encrypt_block(block_b, subkeys)
    bits_diff = bin(int.from_bytes(ct_a, 'big') ^ int.from_bytes(ct_b, 'big')).count('1')
    print(f"Bits diferentes no ciphertext: {bits_diff}/64 ({100*bits_diff/64:.1f}%)")
    assert bits_diff > 20, "Efeito avalanche insuficiente"
    print("Efeito avalanche detectado.  OK")

    print("\nTodos os testes de miniarx.py passaram.")