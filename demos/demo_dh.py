"""
demo_dh.py

Demonstração funcional do protocolo Diffie-Hellman entre duas partes
(Alice e Bob), sobre o grupo G_q.

Roda dois cenários:
    1. Grupo pequeno e didático (p=23, q=11), para acompanhar os
       números manualmente.
    2. Grupo realista, gerado automaticamente com p de 256 bits,
       com medição de tempo de execução.

Executar com:
    python -m demos.demo_dh
"""

import time

from group.subgroup import SubgroupGq
from protocols.diffie_hellman import DiffieHellman


def linha(titulo=""):
    print("\n" + "=" * 70)
    if titulo:
        print(titulo)
        print("=" * 70)


def demo_grupo_pequeno():
    linha("CENÁRIO 1 — Grupo didático (p=23, q=11, g=4)")

    grupo = SubgroupGq(p=23, q=11, g=4)
    dh = DiffieHellman(grupo)

    print(f"\nParâmetros públicos do grupo:")
    print(f"  p (módulo)         = {grupo.p}")
    print(f"  q (ordem do grupo) = {grupo.q}")
    print(f"  g (gerador)        = {grupo.g}")

    print("\n--- Alice gera seu par de chaves ---")
    alice_priv, alice_pub = dh.generate_keypair()
    print(f"  Chave privada (secreta) de Alice: a = {alice_priv}")
    print(f"  Chave pública de Alice:           A = g^a mod p = {alice_pub}")

    print("\n--- Bob gera seu par de chaves ---")
    bob_priv, bob_pub = dh.generate_keypair()
    print(f"  Chave privada (secreta) de Bob: b = {bob_priv}")
    print(f"  Chave pública de Bob:           B = g^b mod p = {bob_pub}")

    print("\n--- Troca de chaves públicas pelo canal (não-seguro) ---")
    print(f"  Alice envia A={alice_pub} para Bob")
    print(f"  Bob envia B={bob_pub} para Alice")
    print("  (um espião que veja A e B não consegue calcular o segredo — problema CDH)")

    print("\n--- Cada parte calcula o segredo compartilhado localmente ---")
    segredo_alice = dh.compute_shared_secret(alice_priv, bob_pub)
    segredo_bob = dh.compute_shared_secret(bob_priv, alice_pub)

    print(f"  Alice calcula: K = B^a mod p = {bob_pub}^{alice_priv} mod {grupo.p} = {segredo_alice}")
    print(f"  Bob   calcula: K = A^b mod p = {alice_pub}^{bob_priv} mod {grupo.p} = {segredo_bob}")

    print("\n--- Verificação ---")
    if segredo_alice == segredo_bob:
        print(f"  Os segredos COINCIDEM: K = {segredo_alice}")
        print("  Diffie-Hellman concluído com sucesso.")
    else:
        print("  ERRO: os segredos não coincidem!")
        raise AssertionError("Falha no protocolo DH")


def demo_grupo_realista():
    linha("CENÁRIO 2 — Grupo realista (p de 256 bits, gerado automaticamente)")

    print("\nGerando grupo G_q com p de 256 bits (pode levar alguns segundos)...")
    t0 = time.perf_counter()
    grupo = SubgroupGq.generate(bits_p=256)
    t_geracao = time.perf_counter() - t0

    print(f"Grupo gerado em {t_geracao:.3f} segundos.")
    print(f"  p (módulo, {grupo.p.bit_length()} bits) = {grupo.p}")
    print(f"  q (ordem,  {grupo.q.bit_length()} bits) = {grupo.q}")
    print(f"  g (gerador)                        = {grupo.g}")

    dh = DiffieHellman(grupo)

    print("\n--- Geração de chaves ---")
    t0 = time.perf_counter()
    alice_priv, alice_pub = dh.generate_keypair()
    t_keygen_alice = time.perf_counter() - t0

    t0 = time.perf_counter()
    bob_priv, bob_pub = dh.generate_keypair()
    t_keygen_bob = time.perf_counter() - t0

    print(f"  Alice: chave gerada em {t_keygen_alice*1000:.3f} ms")
    print(f"  Bob:   chave gerada em {t_keygen_bob*1000:.3f} ms")

    print("\n--- Cálculo do segredo compartilhado ---")
    t0 = time.perf_counter()
    segredo_alice = dh.compute_shared_secret(alice_priv, bob_pub)
    t_secret_alice = time.perf_counter() - t0

    t0 = time.perf_counter()
    segredo_bob = dh.compute_shared_secret(bob_priv, alice_pub)
    t_secret_bob = time.perf_counter() - t0

    print(f"  Alice calculou o segredo em {t_secret_alice*1000:.3f} ms")
    print(f"  Bob   calculou o segredo em {t_secret_bob*1000:.3f} ms")

    print("\n--- Verificação ---")
    assert segredo_alice == segredo_bob
    print(f"  Segredos coincidem (mostrando apenas os primeiros 20 dígitos):")
    print(f"  K = {str(segredo_alice)[:20]}...")
    print(f"  Tamanho do segredo: {segredo_alice.bit_length()} bits")

    linha("RESUMO DE CUSTO COMPUTACIONAL")
    print(f"  Geração do grupo (p, q, g): {t_geracao:.3f} s")
    print(f"  Geração de par de chaves:   ~{(t_keygen_alice+t_keygen_bob)/2*1000:.3f} ms (média)")
    print(f"  Cálculo do segredo:         ~{(t_secret_alice+t_secret_bob)/2*1000:.3f} ms (média)")
    print(f"  Tamanho de p:                {grupo.p.bit_length()} bits")
    print(f"  Tamanho de q (chave priv.):  {grupo.q.bit_length()} bits")


if __name__ == "__main__":
    demo_grupo_pequeno()
    demo_grupo_realista()
    linha("FIM DA DEMONSTRAÇÃO")