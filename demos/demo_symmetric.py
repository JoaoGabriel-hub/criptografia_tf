"""
demo_symmetric.py

Demonstração funcional do MiniARX-64:
    1. Cifração e decifração de mensagem de texto (modo CBC)
    2. Visualização do efeito avalanche (1 bit diferente)
    3. Resumo de análise de desempenho

Executar com:
    python -m demos.demo_symmetric
"""

import os
from symmetric.miniarx import MiniARX64, encrypt_block, BLOCK_SIZE
from symmetric.key_schedule import generate_subkeys


def linha(titulo=""):
    print("\n" + "=" * 70)
    if titulo:
        print(titulo)
        print("=" * 70)


def demo_cifracao():
    linha("CENÁRIO 1 — Cifração e Decifração de Texto (modo CBC)")

    key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    cipher = MiniARX64(key)
    iv = bytes(8)

    msg = b"MiniARX-64: cifra de bloco ARX original."
    print(f"\nChave     : {key.hex()}")
    print(f"IV        : {iv.hex()}")
    print(f"Mensagem  : {msg.decode()!r}")

    ct = cipher.encrypt_cbc(msg, iv=iv)
    print(f"\nCiphertext (hex): {ct.hex()}")
    print(f"Tamanho   : {len(msg)} bytes → {len(ct)} bytes (com IV + padding)")

    pt = cipher.decrypt_cbc(ct)
    print(f"\nDecifrado : {pt.decode()!r}")
    assert pt == msg
    print("Mensagem recuperada com sucesso.  OK")


def demo_avalanche():
    linha("CENÁRIO 2 — Efeito Avalanche (1 bit diferente)")

    key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    subkeys = generate_subkeys(key)

    P0 = bytes.fromhex("0000000000000000")
    P1 = bytes.fromhex("0000000000000001")  # 1 bit diferente

    ct0 = encrypt_block(P0, subkeys)
    ct1 = encrypt_block(P1, subkeys)

    diff = int.from_bytes(ct0, 'big') ^ int.from_bytes(ct1, 'big')
    bits_diff = bin(diff).count('1')

    print(f"\nPlaintext A : {P0.hex()}  (binário: {int.from_bytes(P0,'big'):064b})")
    print(f"Plaintext B : {P1.hex()}  (binário: {int.from_bytes(P1,'big'):064b})")
    print(f"\nCiphertext A: {ct0.hex()}")
    print(f"Ciphertext B: {ct1.hex()}")
    print(f"XOR         : {diff:016x}")
    print(f"\nBits diferentes: {bits_diff}/64 ({100*bits_diff/64:.1f}%)")
    print("Efeito avalanche: mudar 1 bit no plaintext altera ~50% dos bits do ciphertext.")


def demo_nao_determinismo():
    linha("CENÁRIO 3 — Não-Determinismo do Modo CBC")

    key = os.urandom(16)
    cipher = MiniARX64(key)
    msg = b"mesma mensagem"

    ct1 = cipher.encrypt_cbc(msg)
    ct2 = cipher.encrypt_cbc(msg)

    print(f"\nMensagem  : {msg!r}")
    print(f"Cifração 1: {ct1.hex()}")
    print(f"Cifração 2: {ct2.hex()}")
    print(f"Iguais?   : {ct1 == ct2}")
    print("IVs aleatórios garantem ciphertexts distintos a cada cifração.")

    pt = cipher.decrypt_cbc(ct1)
    assert pt == msg
    print(f"Decifração da cifração 1: {pt!r}  OK")


if __name__ == "__main__":
    demo_cifracao()
    demo_avalanche()
    demo_nao_determinismo()
    linha("FIM DA DEMONSTRAÇÃO")