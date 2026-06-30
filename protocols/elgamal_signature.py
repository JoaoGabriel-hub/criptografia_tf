"""
elgamal_signature.py

Implementação autoral da Assinatura Digital ElGamal, construída sobre
o grupo algébrico G_q (group/subgroup.py).

─────────────────────────────────────────────────────────────────────
DIFERENÇA FUNDAMENTAL ENTRE CIFRAÇÃO E ASSINATURA ELGAMAL
─────────────────────────────────────────────────────────────────────
    Cifração ElGamal  → confidencialidade: só o dono da chave privada
                         consegue LER a mensagem.

    Assinatura ElGamal → autenticidade: só o dono da chave privada
                         consegue ASSINAR; qualquer um com a chave
                         pública consegue VERIFICAR.

─────────────────────────────────────────────────────────────────────
ESQUEMA
─────────────────────────────────────────────────────────────────────
    GERAÇÃO DE CHAVES (igual à cifração)
        Escolhe x (privado) em [1, p-2]
        Calcula  h = g^x mod p   (pública)
        Chave pública:  (p, q, g, h)
        Chave privada:  x

    ASSINATURA de uma mensagem (após hash H(msg) → m)
        1. Escolhe k aleatório em [1, p-2], com mdc(k, p-1) = 1
           (k NUNCA pode ser reutilizado — ver nota de segurança)
        2. Calcula r = g^k mod p
        3. Calcula s = k^(-1) * (m - x*r) mod (p-1)
        4. Se r == 0 ou s == 0, descarta e tenta outro k
        5. Assinatura: (r, s)

    VERIFICAÇÃO de (mensagem, (r, s)) com chave pública h
        1. Verifica 0 < r < p  e  0 < s < p-1
        2. Calcula v1 = h^r * r^s mod p
        3. Calcula v2 = g^m mod p
        4. Assinatura válida se e somente se  v1 ≡ v2 (mod p)

    PROVA DE CORRETUDE
        v1 = h^r * r^s mod p
           = (g^x)^r * (g^k)^s mod p
           = g^(x*r + k*s) mod p

        v2 = g^m mod p

        Para que v1 == v2, pelo Pequeno Teorema de Fermat (g^(p-1)≡1),
        basta que:
            x*r + k*s ≡ m  (mod p-1)

        Substituindo s = k^(-1) * (m - x*r) mod (p-1):
            x*r + k * k^(-1) * (m - x*r) = x*r + m - x*r = m  ✓

─────────────────────────────────────────────────────────────────────
NOTA CRÍTICA DE SEGURANÇA — REUTILIZAÇÃO DE k
─────────────────────────────────────────────────────────────────────
    Se o mesmo k for usado para assinar duas mensagens m1 e m2:
        s1 = k^(-1) * (m1 - x*r) mod (p-1)
        s2 = k^(-1) * (m2 - x*r) mod (p-1)
        => s1 - s2 = k^(-1) * (m1 - m2) mod (p-1)
        => k = (m1 - m2) * (s1 - s2)^(-1) mod (p-1)
        => x = (m1 - k*s1) * r^(-1) mod (p-1)

    A chave privada fica exposta com aritmética simples.
    Esse ataque foi usado em 2010 para extrair a chave privada do PS3.

─────────────────────────────────────────────────────────────────────
HASHING
─────────────────────────────────────────────────────────────────────
    A mensagem é hasheada com SHA-256 antes de ser assinada. Isso
    garante segurança para mensagens de qualquer tamanho e que o
    valor m caiba no espaço do grupo.
"""

import hashlib
import random

from group.subgroup import SubgroupGq
from utils.math_utils import extended_gcd, mod_inverse, exp_mod


# ─────────────────────────────────────────────────────────────────────
# Funções auxiliares
# ─────────────────────────────────────────────────────────────────────

def _mdc(a: int, b: int) -> int:
    """Máximo divisor comum via algoritmo de Euclides."""
    g, _, _ = extended_gcd(a, b)
    return abs(g)


def _hash_message(message: bytes, mod: int) -> int:
    """
    Calcula SHA-256 da mensagem e reduz módulo `mod`.

    Parâmetros:
        message: bytes da mensagem
        mod:     módulo de redução (p-1 no esquema ElGamal)

    Retorna:
        inteiro em [1, mod-1]
    """
    digest = hashlib.sha256(message).digest()
    h = int.from_bytes(digest, byteorder="big")
    h = h % mod
    if h == 0:
        h = 1  # caso extremamente raro: hash exatamente 0 mod (p-1)
    return h


# ─────────────────────────────────────────────────────────────────────
# Classe principal
# ─────────────────────────────────────────────────────────────────────

class ElGamalSignature:
    """
    Assinatura Digital ElGamal parametrizada por um grupo G_q.

    Uso típico:
        grupo  = SubgroupGq(p=23, q=11, g=4)
        eg_sig = ElGamalSignature(grupo)

        priv, pub  = eg_sig.generate_keypair()
        sig        = eg_sig.sign(priv, b"minha mensagem")
        valido     = eg_sig.verify(pub, b"minha mensagem", sig)

        assert valido is True
    """

    def __init__(self, group: SubgroupGq):
        """
        Parâmetros:
            group: instância de SubgroupGq já construída (define p, q, g)
        """
        self.group = group

    # ─────────────────────────────────────────────────────────────────
    # Geração de chaves
    # ─────────────────────────────────────────────────────────────────

    def generate_keypair(self):
        """
        Gera par de chaves (privada, pública).

        Chave privada: x em [1, p-2]
        Chave pública: h = g^x mod p

        Retorna:
            (private_key, public_key): tupla (x, h)
        """
        # No esquema de assinatura, x é um expoente em [1, p-2]
        # (diferente da cifração, onde x é em [1, q-1])
        private_key = random.randrange(1, self.group.p - 1)
        public_key = exp_mod(self.group.g, private_key, self.group.p)
        return private_key, public_key

    # ─────────────────────────────────────────────────────────────────
    # Assinatura
    # ─────────────────────────────────────────────────────────────────

    def sign(self, private_key: int, message: bytes):
        """
        Assina uma mensagem usando a chave privada.

        Parâmetros:
            private_key: x — chave privada do assinante
            message:     bytes da mensagem a assinar

        Retorna:
            (r, s): par de inteiros representando a assinatura
        """
        p = self.group.p
        g = self.group.g

        # Hash da mensagem — m é um inteiro em [1, p-2]
        # O módulo da aritmética dos expoentes é (p-1)
        m = _hash_message(message, p - 1)

        while True:
            # k: efêmero aleatório em [1, p-2], coprimo com (p-1)
            # DEVE ser único por assinatura (ver nota de segurança)
            k = random.randrange(1, p - 1)

            if _mdc(k, p - 1) != 1:
                continue  # k não é invertível mod (p-1); tenta outro

            # r = g^k mod p
            r = exp_mod(g, k, p)

            if r == 0:
                continue  # r == 0 invalida a assinatura; tenta outro k

            # s = k^(-1) * (m - x*r) mod (p-1)
            k_inv = mod_inverse(k, p - 1)
            s = (k_inv * (m - private_key * r)) % (p - 1)

            if s == 0:
                continue  # s == 0 invalida a assinatura; tenta outro k

            return (r, s)

    # ─────────────────────────────────────────────────────────────────
    # Verificação
    # ─────────────────────────────────────────────────────────────────

    def verify(self, public_key: int, message: bytes, signature: tuple) -> bool:
        """
        Verifica se uma assinatura é válida.

        Parâmetros:
            public_key: h = g^x mod p (chave pública do assinante)
            message:    bytes da mensagem original (deve ser idêntica)
            signature:  (r, s) — par retornado por sign()

        Retorna:
            True se a assinatura é válida, False caso contrário.
        """
        p = self.group.p
        g = self.group.g

        r, s = signature

        # Verificação básica de domínio
        if not (0 < r < p):
            return False
        if not (0 < s < p - 1):
            return False

        # Recomputa o hash com a mesma função usada ao assinar
        m = _hash_message(message, p - 1)

        # v1 = h^r * r^s mod p
        v1 = (exp_mod(public_key, r, p) * exp_mod(r, s, p)) % p

        # v2 = g^m mod p
        v2 = exp_mod(g, m, p)

        # Assinatura válida se e somente se v1 == v2
        return v1 == v2


# ─────────────────────────────────────────────────────────────────────
# Testes de sanidade (executar: python -m protocols.elgamal_signature)
# ─────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("=== Teste: assinatura com grupo (p=23, q=11, g=4) ===")
    grupo = SubgroupGq(p=23, q=11, g=4)
    eg_sig = ElGamalSignature(grupo)

    priv, pub = eg_sig.generate_keypair()
    print(f"Chave privada: x = {priv}, chave pública: h = {pub}")

    mensagem = b"Ola mundo"
    sig = eg_sig.sign(priv, mensagem)
    print(f"Mensagem: \"{mensagem.decode()}\"")
    print(f"Assinatura: r={sig[0]}, s={sig[1]}")

    assert eg_sig.verify(pub, mensagem, sig) is True
    print("Verificação com chave correta: True  OK")

    assert eg_sig.verify(pub, b"mensagem diferente", sig) is False
    print("Verificação com mensagem alterada: False  OK")

    _, pub_errada = eg_sig.generate_keypair()
    assert eg_sig.verify(pub_errada, mensagem, sig) is False
    print("Verificação com chave errada: False  OK")

    r, s = sig
    assert eg_sig.verify(pub, mensagem, (r + 1, s)) is False
    print("Verificação com assinatura corrompida: False  OK")

    print("\n=== Teste: múltiplas mensagens (grupo maior, sem risco de colisão de hash) ===")
    grupo_m = SubgroupGq.generate(bits_p=64)
    eg_m = ElGamalSignature(grupo_m)
    priv_m, pub_m = eg_m.generate_keypair()
    msgs = [b"alpha", b"beta", b"gamma", b"delta", b"epsilon"]
    for msg in msgs:
        s_ = eg_m.sign(priv_m, msg)
        assert eg_m.verify(pub_m, msg, s_) is True
        assert eg_m.verify(pub_m, msg + b"x", s_) is False
    print(f"{len(msgs)} mensagens assinadas e verificadas corretamente.  OK")

    print("\n=== Teste: não-determinismo (mesmo msg, sigs diferentes) ===")
    s1 = eg_sig.sign(priv, mensagem)
    s2 = eg_sig.sign(priv, mensagem)
    assert s1 != s2
    assert eg_sig.verify(pub, mensagem, s1) is True
    assert eg_sig.verify(pub, mensagem, s2) is True
    print(f"s1={s1}")
    print(f"s2={s2}")
    print("Diferentes, mas ambas válidas.  OK")

    print("\n=== Teste: grupo maior (128 bits) ===")
    grupo_grande = SubgroupGq.generate(bits_p=128)
    eg_sig_grande = ElGamalSignature(grupo_grande)
    priv_g, pub_g = eg_sig_grande.generate_keypair()
    msg = b"Criptografia de chave publica"
    sig_g = eg_sig_grande.sign(priv_g, msg)
    assert eg_sig_grande.verify(pub_g, msg, sig_g) is True
    print(f"Grupo de 128 bits: assinatura válida.  OK")

    print("\nTodos os testes de elgamal_signature.py passaram.")