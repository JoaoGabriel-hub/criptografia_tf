"""
diffie_hellman.py

Implementação autoral do protocolo Diffie-Hellman de troca de chaves,
construído sobre o grupo algébrico G_q (group/subgroup.py).

Protocolo (clássico, adaptado ao grupo G_q):

    Parâmetros públicos: o grupo G_q, com p, q e gerador g.

    Alice escolhe a (privado) em [1, q-1], publica A = g^a mod p
    Bob   escolhe b (privado) em [1, q-1], publica B = g^b mod p

    Segredo compartilhado:
        Alice calcula K = B^a mod p
        Bob   calcula K = A^b mod p
        Ambos chegam a K = g^(ab) mod p

A segurança repousa no problema CDH (Computational Diffie-Hellman) em
G_q: dado g, g^a e g^b, calcular g^(ab) sem conhecer a ou b é
computacionalmente difícil (ver relatório, Seção 1.4).
"""

from group.subgroup import SubgroupGq


class DiffieHellman:
    """
    Protocolo Diffie-Hellman parametrizado por um grupo G_q.

    Uso típico:
        grupo = SubgroupGq(p=23, q=11, g=4)
        dh = DiffieHellman(grupo)

        alice_priv, alice_pub = dh.generate_keypair()
        bob_priv, bob_pub     = dh.generate_keypair()

        segredo_alice = dh.compute_shared_secret(alice_priv, bob_pub)
        segredo_bob   = dh.compute_shared_secret(bob_priv, alice_pub)

        assert segredo_alice == segredo_bob
    """

    def __init__(self, group: SubgroupGq):
        """
        Parâmetros:
            group: instância de SubgroupGq já construída (define p, q, g)
        """
        self.group = group

    def generate_keypair(self):
        """
        Gera um par de chaves (privada, pública) para uma das partes.

        A chave privada é um expoente aleatório a em [1, q-1].
        A chave pública é A = g^a mod p.

        Retorna:
            (private_key, public_key): tupla de inteiros
        """
        private_key = self.group.random_exponent()
        public_key = self.group.power(self.group.g, private_key)
        return private_key, public_key

    def compute_shared_secret(self, own_private_key: int, other_public_key: int) -> int:
        """
        Calcula o segredo compartilhado a partir da própria chave
        privada e da chave pública recebida da outra parte.

            K = (chave_publica_outro)^(chave_privada_propria) mod p

        Parâmetros:
            own_private_key: a própria chave privada (ex.: 'a', de Alice)
            other_public_key: a chave pública recebida da outra parte (ex.: 'B', de Bob)

        Retorna:
            int: o segredo compartilhado K = g^(ab) mod p
        """
        if not self.group.is_member(other_public_key):
            raise ValueError(
                f"Chave pública recebida ({other_public_key}) não pertence ao grupo G_{self.group.q}; "
                f"possível ataque ou parâmetros incompatíveis."
            )
        return self.group.power(other_public_key, own_private_key)


# ----------------------------------------------------------------------
# Testes rápidos de sanidade (executar diretamente: python -m protocols.diffie_hellman)
# ----------------------------------------------------------------------
if __name__ == "__main__":
    print("=== Teste: Diffie-Hellman com grupo pequeno (p=23, q=11, g=4) ===")
    grupo = SubgroupGq(p=23, q=11, g=4)
    dh = DiffieHellman(grupo)

    alice_priv, alice_pub = dh.generate_keypair()
    bob_priv, bob_pub = dh.generate_keypair()

    print(f"Alice: chave privada a={alice_priv}, chave pública A={alice_pub}")
    print(f"Bob:   chave privada b={bob_priv}, chave pública B={bob_pub}")

    segredo_alice = dh.compute_shared_secret(alice_priv, bob_pub)
    segredo_bob = dh.compute_shared_secret(bob_priv, alice_pub)

    print(f"Segredo calculado por Alice: {segredo_alice}")
    print(f"Segredo calculado por Bob:   {segredo_bob}")

    assert segredo_alice == segredo_bob
    print("Os segredos coincidem.  OK")

    print("\n=== Teste: chave pública fora do grupo é rejeitada ===")
    try:
        dh.compute_shared_secret(alice_priv, 5)  # 5 não pertence a G_11 (ver tests/test_group.py)
        assert False, "deveria ter levantado ValueError"
    except ValueError as e:
        print("Chave pública inválida corretamente rejeitada:", e)

    print("\n=== Teste: Diffie-Hellman com grupo gerado automaticamente (maior) ===")
    grupo_grande = SubgroupGq.generate(bits_p=64)
    dh_grande = DiffieHellman(grupo_grande)

    a_priv, a_pub = dh_grande.generate_keypair()
    b_priv, b_pub = dh_grande.generate_keypair()

    seg_a = dh_grande.compute_shared_secret(a_priv, b_pub)
    seg_b = dh_grande.compute_shared_secret(b_priv, a_pub)

    assert seg_a == seg_b
    print(f"Grupo: {grupo_grande}")
    print(f"Segredo compartilhado (64 bits): {seg_a}")
    print("Os segredos coincidem.  OK")

    print("\nTodos os testes de diffie_hellman.py passaram.")