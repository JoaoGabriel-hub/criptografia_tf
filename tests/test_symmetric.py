"""
test_symmetric.py

Testes funcionais (pytest) para o MiniARX-64 (symmetric/).

Verifica:
    - corretude: decrypt(encrypt(m)) == m para ECB e CBC
    - ciphertext diferente do plaintext
    - chaves diferentes → ciphertexts diferentes
    - 1 bit diferente na entrada → ciphertexts diferentes (avalanche básico)
    - padding PKCS#7 (mensagens de tamanhos variados)
    - modo CBC com IV aleatório é não-determinístico
    - rejeição de entradas inválidas (chave curta, bloco errado, etc.)

Rodar com:
    pytest tests/test_symmetric.py -v
"""

import sys
import os
import struct

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import pytest

from symmetric.key_schedule import generate_subkeys, NUM_ROUNDS
from symmetric.miniarx import (
    MiniARX64,
    encrypt_block,
    decrypt_block,
    BLOCK_SIZE,
    KEY_SIZE,
)

# ─────────────────────────────────────────────────────────────────────
# Fixtures
# ─────────────────────────────────────────────────────────────────────

@pytest.fixture
def key():
    return bytes.fromhex("000102030405060708090a0b0c0d0e0f")


@pytest.fixture
def key2():
    return bytes.fromhex("ff0102030405060708090a0b0c0d0e0f")


@pytest.fixture
def subkeys(key):
    return generate_subkeys(key)


@pytest.fixture
def cipher(key):
    return MiniARX64(key)


# ─────────────────────────────────────────────────────────────────────
# Key Schedule
# ─────────────────────────────────────────────────────────────────────

def test_subkeys_quantidade_correta(subkeys):
    assert len(subkeys) == NUM_ROUNDS


def test_subkeys_determinismo(key):
    assert generate_subkeys(key) == generate_subkeys(key)


def test_subkeys_distintas_para_chaves_distintas(key, key2):
    assert generate_subkeys(key) != generate_subkeys(key2)


def test_subkeys_ka_sao_distintas_entre_rodadas(subkeys):
    ka_list = [ka for ka, _ in subkeys]
    assert len(set(ka_list)) == NUM_ROUNDS


def test_subkeys_kb_sao_distintas_entre_rodadas(subkeys):
    kb_list = [kb for _, kb in subkeys]
    assert len(set(kb_list)) == NUM_ROUNDS


def test_chave_invalida_levanta_erro():
    with pytest.raises(ValueError):
        MiniARX64(b"chave_curta")


# ─────────────────────────────────────────────────────────────────────
# Cifração/Decifração de bloco único
# ─────────────────────────────────────────────────────────────────────

def test_decrypt_bloco_recupera_plaintext(subkeys):
    block = bytes.fromhex("0011223344556677")
    ct = encrypt_block(block, subkeys)
    assert decrypt_block(ct, subkeys) == block


def test_ciphertext_diferente_do_plaintext(subkeys):
    block = bytes.fromhex("0011223344556677")
    ct = encrypt_block(block, subkeys)
    assert ct != block


def test_chaves_diferentes_blocos_diferentes(key, key2):
    block = bytes.fromhex("aabbccddeeff0011")
    ct1 = encrypt_block(block, generate_subkeys(key))
    ct2 = encrypt_block(block, generate_subkeys(key2))
    assert ct1 != ct2


def test_blocos_diferentes_ciphertexts_diferentes(subkeys):
    b1 = bytes.fromhex("0000000000000000")
    b2 = bytes.fromhex("0000000000000001")
    assert encrypt_block(b1, subkeys) != encrypt_block(b2, subkeys)


def test_bloco_tamanho_errado_levanta_erro(subkeys):
    with pytest.raises(ValueError):
        encrypt_block(b"curto", subkeys)


def test_multiplos_blocos_distintos(subkeys):
    blocos = [struct.pack(">Q", i) for i in range(16)]
    ciphertexts = [encrypt_block(b, subkeys) for b in blocos]
    assert len(set(ciphertexts)) == 16


# ─────────────────────────────────────────────────────────────────────
# Efeito Avalanche
# ─────────────────────────────────────────────────────────────────────

def test_avalanche_1_bit_plaintext(subkeys):
    """Mudar 1 bit no plaintext deve alterar pelo menos 20 bits no ciphertext."""
    b0 = bytes(8)
    b1 = bytes([0]*7 + [1])
    ct0 = encrypt_block(b0, subkeys)
    ct1 = encrypt_block(b1, subkeys)
    diff = bin(int.from_bytes(ct0,'big') ^ int.from_bytes(ct1,'big')).count('1')
    assert diff >= 20, f"Avalanche insuficiente: apenas {diff}/64 bits diferentes"


def test_avalanche_medio_proximo_50_porcento(key):
    """
    Media de 1000 pares com 1 bit diferente deve alterar ~50% dos bits.
    Aceita entre 40% e 60%.
    """
    import random
    subkeys = generate_subkeys(key)
    total_bits = 0
    N = 1000
    for _ in range(N):
        b0 = random.randbytes(8)
        # Flipa um bit aleatório
        idx = random.randrange(8)
        bit = random.randrange(8)
        b1 = bytearray(b0)
        b1[idx] ^= (1 << bit)
        ct0 = encrypt_block(bytes(b0), subkeys)
        ct1 = encrypt_block(bytes(b1), subkeys)
        diff = bin(int.from_bytes(ct0,'big') ^ int.from_bytes(ct1,'big')).count('1')
        total_bits += diff
    media = total_bits / N
    assert 25 <= media <= 39, f"Media de bits diferentes fora do range: {media:.1f}/64"


# ─────────────────────────────────────────────────────────────────────
# Modo ECB
# ─────────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("msg", [
    b"a",
    b"hello",
    b"mensagem de exatamente 8bytes!!",
    b"Criptografia simetrica original",
    b"x" * 64,
])
def test_ecb_decrypt_recupera_mensagem(cipher, msg):
    ct = cipher.encrypt(msg, mode='ecb')
    assert cipher.decrypt(ct, mode='ecb') == msg


def test_ecb_determinístico_mesma_chave(cipher):
    msg = b"teste deterministico"
    assert cipher.encrypt(msg, mode='ecb') == cipher.encrypt(msg, mode='ecb')


def test_ecb_chaves_diferentes_resultados_diferentes(key, key2):
    msg = b"mesma mensagem"
    ct1 = MiniARX64(key).encrypt(msg, mode='ecb')
    ct2 = MiniARX64(key2).encrypt(msg, mode='ecb')
    assert ct1 != ct2


# ─────────────────────────────────────────────────────────────────────
# Modo CBC
# ─────────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("msg", [
    b"a",
    b"hello world",
    b"Criptografia simetrica original",
    b"y" * 64,
])
def test_cbc_decrypt_recupera_mensagem(cipher, msg):
    ct = cipher.encrypt(msg, mode='cbc')
    assert cipher.decrypt(ct, mode='cbc') == msg


def test_cbc_nao_deterministico_sem_iv(cipher):
    """CBC com IV aleatório não deve produzir o mesmo ciphertext duas vezes."""
    msg = b"mesma mensagem"
    ct1 = cipher.encrypt(msg, mode='cbc')
    ct2 = cipher.encrypt(msg, mode='cbc')
    assert ct1 != ct2


def test_cbc_deterministico_com_iv_fixo(cipher):
    msg = b"mesma mensagem"
    iv = bytes(8)
    ct1 = cipher.encrypt_cbc(msg, iv=iv)
    ct2 = cipher.encrypt_cbc(msg, iv=iv)
    assert ct1 == ct2


def test_cbc_iv_diferente_ciphertext_diferente(cipher):
    msg = b"mesma mensagem"
    iv1 = bytes(8)
    iv2 = bytes([1] + [0]*7)
    ct1 = cipher.encrypt_cbc(msg, iv=iv1)
    ct2 = cipher.encrypt_cbc(msg, iv=iv2)
    assert ct1 != ct2


def test_cbc_propagacao_de_erro():
    """Corromper 1 bloco cifrado deve afetar apenas aquele bloco e o próximo."""
    key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    cipher = MiniARX64(key)
    msg = b"bloco1--bloco2--bloco3--"  # 3 blocos de 8 bytes
    ct = bytearray(cipher.encrypt_cbc(msg))
    # Corrompe o segundo bloco (bytes 8-15 do ciphertext, após o IV)
    ct[BLOCK_SIZE + 1] ^= 0xFF
    pt = cipher.decrypt_cbc(bytes(ct))
    # Bloco 1 (bytes 0-7) deve estar corrompido; bloco 3 deve estar intacto
    assert pt[16:24] == msg[16:24], "Bloco 3 não deveria ser afetado"


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))