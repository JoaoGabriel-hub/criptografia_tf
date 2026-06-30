"""
demo_elgamal.py

Demonstração funcional do criptossistema ElGamal entre duas partes
(Alice e Bob), sobre o grupo G_q.

Cenários:
    1. Grupo didático (p=23, q=11) — números pequenos, fáceis de auditar.
    2. Cifração de uma mensagem de texto simples (string) usando conversão
       texto <-> inteiro, com grupo realista de 256 bits.
    3. Evidência do não-determinismo: a mesma mensagem cifrada duas vezes
       produz criptogramas distintos (propriedade fundamental de segurança).

Executar com:
    python -m demos.demo_elgamal
"""

import time

from group.subgroup import SubgroupGq
from protocols.elgamal import ElGamal, text_to_int, int_to_text


def linha(titulo=""):
    print("\n" + "=" * 70)
    if titulo:
        print(titulo)
        print("=" * 70)


def demo_grupo_pequeno():
    linha("CENÁRIO 1 — Grupo didático (p=23, q=11, g=4)")

    grupo = SubgroupGq(p=23, q=11, g=4)
    eg = ElGamal(grupo)

    print(f"\nParâmetros públicos do grupo:")
    print(f"  p (módulo)         = {grupo.p}")
    print(f"  q (ordem do grupo) = {grupo.q}")
    print(f"  g (gerador)        = {grupo.g}")

    print("\n--- Alice gera seu par de chaves ---")
    alice_priv, alice_pub = eg.generate_keypair()
    print(f"  Chave privada (secreta): x = {alice_priv}")
    print(f"  Chave pública:           h = g^x mod p = {alice_pub}")
    print(f"  Alice divulga h={alice_pub} publicamente.")

    print("\n--- Bob escolhe uma mensagem e cifra para Alice ---")
    # Usa g^3 mod p como mensagem — garantidamente membro do grupo
    m = grupo.power(grupo.g, 3)
    print(f"  Mensagem original de Bob:  m = {m}  (= g^3 mod p)")

    c1, c2 = eg.encrypt(alice_pub, m)
    print(f"  Bob cifra com a chave pública de Alice:")
    print(f"    Escolhe k aleatório (secreto)")
    print(f"    c1 = g^k mod p       = {c1}")
    print(f"    c2 = m * h^k mod p   = {c2}")
    print(f"  Bob envia o criptograma: ({c1}, {c2})")

    print("\n--- Alice decifra com sua chave privada ---")
    print(f"  Recalcula s = c1^x mod p = {c1}^{alice_priv} mod {grupo.p}")
    s = grupo.power(c1, alice_priv)
    print(f"  s = {s}")
    print(f"  Recupera m = c2 * s^(-1) mod p = {c2} * {grupo.inverse(s)} mod {grupo.p}")
    m_dec = eg.decrypt(alice_priv, (c1, c2))
    print(f"  Mensagem decifrada: m = {m_dec}")

    assert m_dec == m
    print(f"\n  Mensagem original == Mensagem decifrada: {m} == {m_dec}  OK")


def demo_nao_determinismo():
    linha("CENÁRIO 2 — Não-determinismo: mesma mensagem, criptogramas diferentes")

    grupo = SubgroupGq(p=23, q=11, g=4)
    eg = ElGamal(grupo)
    _, pub = eg.generate_keypair()

    m = grupo.power(grupo.g, 5)
    print(f"\nMensagem original: m = {m}")
    print("\nCifrando a mesma mensagem 5 vezes com a mesma chave pública:")

    criptogramas = []
    for i in range(1, 6):
        ct = eg.encrypt(pub, m)
        criptogramas.append(ct)
        print(f"  Cifração {i}: (c1={ct[0]}, c2={ct[1]})")

    todos_diferentes = len(set(criptogramas)) == len(criptogramas)
    print(f"\nTodos os criptogramas são distintos: {todos_diferentes}")
    print("Isso é esperado: o k efêmero é aleatório a cada cifração.")
    print("Consequência: ElGamal é semanticamente seguro sob DDH (IND-CPA).")


def demo_texto_grupo_realista():
    linha("CENÁRIO 3 — Cifração de texto com grupo de 256 bits")

    print("\nGerando grupo G_q com p de 256 bits...")
    t0 = time.perf_counter()
    grupo = SubgroupGq.generate(bits_p=256)
    t_ger = time.perf_counter() - t0
    print(f"Grupo gerado em {t_ger:.2f}s.")
    print(f"  p ({grupo.p.bit_length()} bits), q ({grupo.q.bit_length()} bits)")

    eg = ElGamal(grupo)

    print("\n--- Alice gera suas chaves ---")
    t0 = time.perf_counter()
    alice_priv, alice_pub = eg.generate_keypair()
    t_key = time.perf_counter() - t0
    print(f"  Chaves geradas em {t_key*1000:.3f} ms")

    # Mensagem como elemento do grupo (via exponenciação com índice derivado da string)
    # Para simplicidade da demo: usamos um elemento aleatório do grupo como "chave de sessão"
    # e mostramos a cifração desse inteiro
    print("\n--- Bob cifra uma mensagem para Alice ---")
    mensagem_texto = "Ola Alice"
    m_int = text_to_int(mensagem_texto)
    print(f"  Mensagem original (texto):  \"{mensagem_texto}\"")
    print(f"  Mensagem como inteiro:       {m_int}")

    # Para ElGamal puro, a mensagem deve pertencer ao grupo.
    # Aqui usamos a mensagem como inteiro simples (válido para p grande,
    # onde m < p com folga para strings curtas — e a decifração sempre
    # funciona algebricamente). No relatório, discutir que o uso correto
    # em produção seria usar ElGamal como KEM.
    t0 = time.perf_counter()
    ct = eg.encrypt(alice_pub, m_int)
    t_enc = time.perf_counter() - t0

    print(f"  Cifração realizada em {t_enc*1000:.3f} ms")
    print(f"  Criptograma:")
    print(f"    c1 = {str(ct[0])[:30]}... ({ct[0].bit_length()} bits)")
    print(f"    c2 = {str(ct[1])[:30]}... ({ct[1].bit_length()} bits)")

    print("\n--- Alice decifra ---")
    t0 = time.perf_counter()
    m_dec = eg.decrypt(alice_priv, ct)
    t_dec = time.perf_counter() - t0

    mensagem_recuperada = int_to_text(m_dec)
    print(f"  Decifração realizada em {t_dec*1000:.3f} ms")
    print(f"  Inteiro decifrado: {m_dec}")
    print(f"  Texto recuperado:  \"{mensagem_recuperada}\"")

    assert m_dec == m_int
    assert mensagem_recuperada == mensagem_texto
    print(f"\n  Mensagem recuperada com sucesso.  OK")

    linha("RESUMO DE CUSTO COMPUTACIONAL")
    print(f"  Geração do grupo (p, q, g): {t_ger:.3f} s")
    print(f"  Geração de par de chaves:   {t_key*1000:.3f} ms")
    print(f"  Cifração:                   {t_enc*1000:.3f} ms")
    print(f"  Decifração:                 {t_dec*1000:.3f} ms")
    print(f"  Tamanho de p:               {grupo.p.bit_length()} bits")
    print(f"  Tamanho do criptograma:     2 × {grupo.p.bit_length()} bits = {2*grupo.p.bit_length()} bits")


if __name__ == "__main__":
    demo_grupo_pequeno()
    demo_nao_determinismo()
    demo_texto_grupo_realista()
    linha("FIM DA DEMONSTRAÇÃO")