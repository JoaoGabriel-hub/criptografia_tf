"""
avalanche.py

Análise do Efeito Avalanche do MiniARX-64.

O efeito avalanche é uma propriedade desejável em cifras de bloco:
mudar 1 bit na entrada (plaintext ou chave) deve alterar
aproximadamente 50% dos bits na saída (ciphertext).

Este módulo realiza três análises:

    1. Avalanche de plaintext:
       Para N pares (P, P'), onde P' = P com 1 bit flipado,
       mede quantos bits diferem em encrypt(P) vs encrypt(P').

    2. Avalanche de chave:
       Para N pares (K, K'), onde K' = K com 1 bit flipado,
       mede quantos bits diferem em encrypt_K(P) vs encrypt_K'(P).

    3. Distribuição por bit:
       Para cada posição de bit do bloco (0-63), conta quantas
       vezes aquele bit específico mudou no ciphertext ao flipar
       1 bit do plaintext — ideal: ~50% das vezes.
"""

import random
import statistics

from symmetric.key_schedule import generate_subkeys
from symmetric.miniarx import encrypt_block, BLOCK_SIZE


# ─────────────────────────────────────────────────────────────────────
# Utilitários
# ─────────────────────────────────────────────────────────────────────

def _flip_bit(data: bytes, bit_pos: int) -> bytes:
    """Flipa o bit na posição `bit_pos` (0 = MSB do primeiro byte)."""
    byte_idx = bit_pos // 8
    bit_idx  = 7 - (bit_pos % 8)
    b = bytearray(data)
    b[byte_idx] ^= (1 << bit_idx)
    return bytes(b)


def _hamming(a: bytes, b: bytes) -> int:
    """Distância de Hamming em bits entre dois byte strings."""
    xor = int.from_bytes(a, 'big') ^ int.from_bytes(b, 'big')
    return bin(xor).count('1')


# ─────────────────────────────────────────────────────────────────────
# Análise 1 — Avalanche de plaintext
# ─────────────────────────────────────────────────────────────────────

def avalanche_plaintext(key: bytes, n_samples: int = 10_000) -> dict:
    """
    Mede o efeito avalanche variando 1 bit do plaintext.

    Para cada amostra:
        - sorteia um plaintext P aleatório de 8 bytes
        - sorteia uma posição de bit aleatória (0-63)
        - cifra P e P' (P com esse bit flipado) com a mesma chave
        - conta quantos bits diferem nos ciphertexts

    Retorna dict com:
        mean   : média de bits diferentes (esperado ~32 de 64)
        std    : desvio padrão
        min    : mínimo observado
        max    : máximo observado
        pct    : média como porcentagem do bloco (esperado ~50%)
        samples: lista completa de contagens
    """
    subkeys = generate_subkeys(key)
    diffs = []

    for _ in range(n_samples):
        P  = random.randbytes(BLOCK_SIZE)
        bp = random.randrange(64)
        Pp = _flip_bit(P, bp)

        ct  = encrypt_block(P,  subkeys)
        ctp = encrypt_block(Pp, subkeys)

        diffs.append(_hamming(ct, ctp))

    return {
        "mean"   : statistics.mean(diffs),
        "std"    : statistics.stdev(diffs),
        "min"    : min(diffs),
        "max"    : max(diffs),
        "pct"    : statistics.mean(diffs) / 64 * 100,
        "samples": diffs,
    }


# ─────────────────────────────────────────────────────────────────────
# Análise 2 — Avalanche de chave
# ─────────────────────────────────────────────────────────────────────

def avalanche_key(plaintext: bytes, n_samples: int = 10_000) -> dict:
    """
    Mede o efeito avalanche variando 1 bit da chave.

    Para cada amostra:
        - sorteia uma chave K aleatória de 16 bytes
        - sorteia uma posição de bit aleatória (0-127)
        - cifra o mesmo plaintext com K e K' (K com bit flipado)
        - conta quantos bits diferem nos ciphertexts

    Retorna o mesmo formato de dict que avalanche_plaintext().
    """
    diffs = []

    for _ in range(n_samples):
        K  = random.randbytes(16)
        bk = random.randrange(128)
        Kp = _flip_bit(K, bk)

        ct  = encrypt_block(plaintext, generate_subkeys(K))
        ctp = encrypt_block(plaintext, generate_subkeys(Kp))

        diffs.append(_hamming(ct, ctp))

    return {
        "mean"   : statistics.mean(diffs),
        "std"    : statistics.stdev(diffs),
        "min"    : min(diffs),
        "max"    : max(diffs),
        "pct"    : statistics.mean(diffs) / 64 * 100,
        "samples": diffs,
    }


# ─────────────────────────────────────────────────────────────────────
# Análise 3 — Distribuição por bit de saída
# ─────────────────────────────────────────────────────────────────────

def bit_flip_distribution(key: bytes, n_samples: int = 5_000) -> list:
    """
    Para cada um dos 64 bits de saída, mede a fração de vezes que
    ele é afetado ao flipar 1 bit aleatório do plaintext.

    Ideal: cada bit de saída deve mudar em ~50% das amostras,
    indicando que nenhum bit é privilegiado ou ignorado pela cifra.

    Retorna:
        lista de 64 floats, cada um representando a porcentagem de
        vezes que aquele bit de saída mudou (0.0 a 100.0).
    """
    subkeys = generate_subkeys(key)
    bit_counts = [0] * 64   # bit_counts[i] = vezes que o bit i mudou

    for _ in range(n_samples):
        P  = random.randbytes(BLOCK_SIZE)
        bp = random.randrange(64)
        Pp = _flip_bit(P, bp)

        ct  = int.from_bytes(encrypt_block(P,  subkeys), 'big')
        ctp = int.from_bytes(encrypt_block(Pp, subkeys), 'big')
        diff = ct ^ ctp

        for i in range(64):
            if diff & (1 << (63 - i)):
                bit_counts[i] += 1

    return [c / n_samples * 100 for c in bit_counts]


# ─────────────────────────────────────────────────────────────────────
# Execução direta
# ─────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    KEY = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    PT  = bytes.fromhex("0011223344556677")

    print("=" * 60)
    print("ANÁLISE DE EFEITO AVALANCHE — MiniARX-64")
    print("=" * 60)

    print("\n[1] Avalanche de Plaintext (10.000 amostras)")
    r = avalanche_plaintext(KEY, n_samples=10_000)
    print(f"    Média de bits alterados : {r['mean']:.2f} / 64  ({r['pct']:.2f}%)")
    print(f"    Desvio padrão           : {r['std']:.2f}")
    print(f"    Mínimo / Máximo         : {r['min']} / {r['max']}")

    print("\n[2] Avalanche de Chave (10.000 amostras)")
    r2 = avalanche_key(PT, n_samples=10_000)
    print(f"    Média de bits alterados : {r2['mean']:.2f} / 64  ({r2['pct']:.2f}%)")
    print(f"    Desvio padrão           : {r2['std']:.2f}")
    print(f"    Mínimo / Máximo         : {r2['min']} / {r2['max']}")

    print("\n[3] Distribuição por bit de saída (5.000 amostras)")
    dist = bit_flip_distribution(KEY, n_samples=5_000)
    min_bit = min(dist)
    max_bit = max(dist)
    mean_bit = sum(dist) / len(dist)
    print(f"    Porcentagem média de mudança por bit : {mean_bit:.2f}%")
    print(f"    Mínimo / Máximo por bit              : {min_bit:.2f}% / {max_bit:.2f}%")
    below_40 = sum(1 for x in dist if x < 40)
    above_60 = sum(1 for x in dist if x > 60)
    print(f"    Bits abaixo de 40% : {below_40}")
    print(f"    Bits acima de 60%  : {above_60}")

    print("\nAnálise de avalanche concluída.")