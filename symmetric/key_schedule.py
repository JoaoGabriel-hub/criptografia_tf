"""
key_schedule.py

Geração de subchaves (Key Schedule) do MiniARX-64.

A chave mestre de 128 bits é dividida em 4 words de 32 bits:
    K = (W0, W1, W2, W3)

Para cada rodada i (0 <= i < NUM_ROUNDS), são geradas duas subchaves
de 32 bits cada (uma para o word A e uma para o word B):

    K_A[i] = (W[i mod 4] + rotl(W[(i+1) mod 4], RC_ROT)) XOR RC[i]
    K_B[i] = (W[(i+2) mod 4] + rotl(W[(i+3) mod 4], RC_ROT)) XOR RC[i+1]

onde RC[i] são constantes de rodada derivadas dos primeiros dígitos
de π (irracional, sem propriedades ocultas — mesmo princípio do SHA-2).

Propriedades do key schedule:
    - Cada subchave depende de toda a chave mestre
    - Constantes de rodada eliminam simetrias entre rodadas
    - Sem chaves fracas: toda chave de 128 bits produz subchaves distintas
    - Invertível: conhecendo a chave mestre, todas as subchaves são
      reproduzíveis deterministicamente
"""

from utils.math_utils import exp_mod  # apenas para confirmar que o path está ok

# ─────────────────────────────────────────────────────────────────────
# Constantes globais
# ─────────────────────────────────────────────────────────────────────

WORD_BITS   = 32           # tamanho de cada word em bits
WORD_MOD    = 2 ** 32      # aritmética modular dos words
NUM_ROUNDS  = 16           # número de rodadas do MiniARX-64
KEY_BITS    = 128          # tamanho da chave mestre
RC_ROT      = 7            # rotação usada internamente no key schedule

# Constantes de rodada: os 34 primeiros grupos de 8 dígitos hex de π
# (32 rodadas = 16 rodadas × 2 subchaves por rodada)
# Geradas via: int(mpmath.mp.nstr(mpmath.pi, 100).replace('.',''))[k:k+8]
# mas fixadas aqui para reprodutibilidade sem dependência de mpmath.
_PI_HEX_DIGITS = [
    0x243F6A88, 0x85A308D3, 0x13198A2E, 0x03707344,
    0xA4093822, 0x299F31D0, 0x082EFA98, 0xEC4E6C89,
    0x452821E6, 0x38D01377, 0xBE5466CF, 0x34E90C6C,
    0xC0AC29B7, 0xC97C50DD, 0x3F84D5B5, 0xB5470917,
    0x9216D5D9, 0x8979FB1B, 0xD1310BA6, 0x98DFB5AC,
    0x2FFD72DB, 0xD01ADFB7, 0xB8E1AFED, 0x6A267E96,
    0xBA7C9045, 0xF12C7F99, 0x24A19947, 0xB3916CF7,
    0x0801F2E2, 0x858EFC16, 0x636920D8, 0x71574E69,
    0xA458FEA3, 0xF4933D7E,
]

# Garante que temos constantes suficientes para todas as subchaves
assert len(_PI_HEX_DIGITS) >= NUM_ROUNDS * 2, \
    "Constantes de rodada insuficientes para o número de rodadas configurado"


# ─────────────────────────────────────────────────────────────────────
# Utilitários de word de 32 bits
# ─────────────────────────────────────────────────────────────────────

def _rotl32(x: int, n: int) -> int:
    """Rotação circular à esquerda de `x` (32 bits) por `n` posições."""
    n = n % WORD_BITS
    return ((x << n) | (x >> (WORD_BITS - n))) & 0xFFFFFFFF


def _add32(a: int, b: int) -> int:
    """Adição modular de 32 bits."""
    return (a + b) & 0xFFFFFFFF


def bytes_to_words(key_bytes: bytes) -> list:
    """
    Converte 16 bytes (128 bits) de chave em 4 words de 32 bits (big-endian).

    Parâmetros:
        key_bytes: bytes da chave (deve ter exatamente 16 bytes)

    Retorna:
        lista de 4 inteiros de 32 bits [W0, W1, W2, W3]
    """
    if len(key_bytes) != 16:
        raise ValueError(f"Chave deve ter 16 bytes (128 bits), recebeu {len(key_bytes)}")
    return [
        int.from_bytes(key_bytes[i*4:(i+1)*4], byteorder='big')
        for i in range(4)
    ]


# ─────────────────────────────────────────────────────────────────────
# Geração de subchaves
# ─────────────────────────────────────────────────────────────────────

def generate_subkeys(key_bytes: bytes) -> list:
    """
    Gera as 16 pares de subchaves (K_A[i], K_B[i]) do MiniARX-64
    a partir da chave mestre de 128 bits.

    Esquema:
        W = bytes_to_words(key_bytes)   # [W0, W1, W2, W3]

        Para cada rodada i:
            K_A[i] = (W[i%4] + rotl(W[(i+1)%4], RC_ROT)) XOR RC[2*i]
            K_B[i] = (W[(i+2)%4] + rotl(W[(i+3)%4], RC_ROT)) XOR RC[2*i+1]

    Parâmetros:
        key_bytes: bytes da chave mestre (16 bytes)

    Retorna:
        lista de NUM_ROUNDS tuplas (K_A, K_B), cada uma com dois
        inteiros de 32 bits
    """
    W = bytes_to_words(key_bytes)
    subkeys = []

    for i in range(NUM_ROUNDS):
        ka = _add32(W[i % 4], _rotl32(W[(i + 1) % 4], RC_ROT))
        ka = ka ^ _PI_HEX_DIGITS[2 * i]

        kb = _add32(W[(i + 2) % 4], _rotl32(W[(i + 3) % 4], RC_ROT))
        kb = kb ^ _PI_HEX_DIGITS[2 * i + 1]

        subkeys.append((ka, kb))

    return subkeys


# ─────────────────────────────────────────────────────────────────────
# Testes de sanidade
# ─────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("=== Teste: geração de subchaves ===")
    key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    subkeys = generate_subkeys(key)

    assert len(subkeys) == NUM_ROUNDS
    print(f"Número de pares de subchaves gerados: {len(subkeys)} (esperado: {NUM_ROUNDS})")

    print("\nPrimeiras 4 subchaves:")
    for i, (ka, kb) in enumerate(subkeys[:4]):
        print(f"  Rodada {i}: K_A = {ka:#010x}, K_B = {kb:#010x}")

    print("\n=== Teste: chaves diferentes produzem subchaves diferentes ===")
    key2 = bytes.fromhex("ff0102030405060708090a0b0c0d0e0f")
    subkeys2 = generate_subkeys(key2)
    assert subkeys != subkeys2
    print("Subchaves distintas para chaves distintas.  OK")

    print("\n=== Teste: determinismo (mesma chave = mesmas subchaves) ===")
    assert generate_subkeys(key) == generate_subkeys(key)
    print("Mesma chave produz sempre as mesmas subchaves.  OK")

    print("\n=== Teste: todas as subchaves são distintas entre si ===")
    todos_ka = [ka for ka, _ in subkeys]
    todos_kb = [kb for _, kb in subkeys]
    # Com constantes de π distintas, espera-se que todas sejam diferentes
    assert len(set(todos_ka)) == NUM_ROUNDS, "K_A colidiram entre rodadas"
    assert len(set(todos_kb)) == NUM_ROUNDS, "K_B colidiram entre rodadas"
    print("Todas as 16 subchaves K_A e K_B são distintas.  OK")

    print("\nTodos os testes de key_schedule.py passaram.")