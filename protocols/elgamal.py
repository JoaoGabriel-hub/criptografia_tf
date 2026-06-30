"""
elgamal.py

Implementação autoral do criptossistema ElGamal, construído sobre o
grupo algébrico G_q (group/subgroup.py).

Esquema (adaptado ao grupo G_q):

    GERAÇÃO DE CHAVES
        Escolhe x (privado) em [1, q-1]
        Calcula  h = g^x mod p  (pública)
        Chave pública:  (p, q, g, h)
        Chave privada:  x

    CIFRAÇÃO (por Bob, usando a chave pública de Alice)
        Escolhe k (efêmero, aleatório) em [1, q-1]
        Calcula c1 = g^k mod p                  (parte 1 do criptograma)
        Calcula s  = h^k mod p                  (segredo efêmero compartilhado)
        Calcula c2 = (m * s) mod p              (parte 2 do criptograma)
        Envia criptograma: (c1, c2)

    DECIFRAÇÃO (por Alice, usando sua chave privada x)
        Recalcula s  = c1^x mod p               (recupera o segredo efêmero)
        Recupera  m  = c2 * s^(-1) mod p

    SEGURANÇA
        A segurança repousa no problema DDH em G_q: um adversário que
        veja (g, g^x, g^k, m * h^k) não consegue recuperar m sem
        resolver o DDH (ver relatório, Seção 1.4).

    NOTA SOBRE O ESPAÇO DE MENSAGENS
        A mensagem m deve ser um inteiro em [1, p-1] que pertença a G_q,
        ou seja, m^q ≡ 1 (mod p). Para mensagens arbitrárias (strings,
        bytes), converta-as para inteiro e use o ElGamal como encapsulador
        de chave (KEM), enviando a chave simétrica cifrada via ElGamal e o
        conteúdo via cifra simétrica. A demo ilustra essa conversão básica.
"""

from group.subgroup import SubgroupGq


class ElGamal:
    """
    Criptossistema ElGamal parametrizado por um grupo G_q.

    Uso típico:
        grupo = SubgroupGq(p=23, q=11, g=4)
        eg = ElGamal(grupo)

        priv, pub = eg.generate_keypair()
        c1, c2    = eg.encrypt(pub, mensagem_int)
        m         = eg.decrypt(priv, (c1, c2))

        assert m == mensagem_int
    """

    def __init__(self, group: SubgroupGq):
        """
        Parâmetros:
            group: instância de SubgroupGq já construída (define p, q, g)
        """
        self.group = group

    # ------------------------------------------------------------------
    # Geração de chaves
    # ------------------------------------------------------------------

    def generate_keypair(self):
        """
        Gera um par de chaves ElGamal.

        Chave privada: x — inteiro aleatório em [1, q-1]
        Chave pública: h = g^x mod p

        Retorna:
            (private_key, public_key): tupla de inteiros (x, h)
        """
        private_key = self.group.random_exponent()
        public_key = self.group.power(self.group.g, private_key)
        return private_key, public_key

    # ------------------------------------------------------------------
    # Cifração
    # ------------------------------------------------------------------

    def encrypt(self, public_key: int, message: int):
        """
        Cifra um inteiro `message` usando a chave pública `public_key`.

        Parâmetros:
            public_key: h = g^x mod p (chave pública do destinatário)
            message: inteiro m em [1, p-1].
                     Idealmente m pertence a G_q; se não pertencer, a
                     decifração ainda funciona (m * s * s^-1 = m), mas
                     a segurança semântica é formalmente garantida apenas
                     para m em G_q.

        Retorna:
            (c1, c2): par de inteiros representando o criptograma
                c1 = g^k mod p       (chave pública efêmera)
                c2 = m * h^k mod p   (mensagem mascarada)
        """
        if not (1 <= message <= self.group.p - 1):
            raise ValueError(
                f"Mensagem m={message} fora do intervalo válido [1, {self.group.p - 1}]"
            )
        if not self.group.is_member(public_key):
            raise ValueError(
                f"Chave pública h={public_key} não pertence ao grupo G_{self.group.q}"
            )

        # k: expoente efêmero — DEVE ser aleatório e secreto a cada cifração
        k = self.group.random_exponent()

        c1 = self.group.power(self.group.g, k)          # g^k mod p
        s = self.group.power(public_key, k)              # h^k = g^(xk) mod p
        c2 = self.group.operate(message, s)              # m * s mod p

        return c1, c2

    # ------------------------------------------------------------------
    # Decifração
    # ------------------------------------------------------------------

    def decrypt(self, private_key: int, ciphertext: tuple) -> int:
        """
        Decifra um criptograma usando a chave privada.

        Parâmetros:
            private_key: x — chave privada do destinatário
            ciphertext:  (c1, c2) — par retornado por encrypt()

        Retorna:
            int: a mensagem original m
        """
        c1, c2 = ciphertext

        if not self.group.is_member(c1):
            raise ValueError(
                f"Criptograma inválido: c1={c1} não pertence ao grupo"
            )

        # Recalcula o segredo efêmero: s = c1^x = (g^k)^x = g^(kx) mod p
        s = self.group.power(c1, private_key)

        # Recupera a mensagem: m = c2 * s^(-1) mod p
        s_inv = self.group.inverse(s)
        message = self.group.operate(c2, s_inv)

        return message


# ----------------------------------------------------------------------
# Funções auxiliares de conversão texto <-> inteiro
# (usadas apenas nas demos; não fazem parte do protocolo central)
# ----------------------------------------------------------------------

def text_to_int(text: str) -> int:
    """Converte uma string UTF-8 para inteiro (big-endian)."""
    return int.from_bytes(text.encode("utf-8"), byteorder="big")


def int_to_text(n: int) -> str:
    """Converte um inteiro de volta para string UTF-8."""
    length = (n.bit_length() + 7) // 8
    return n.to_bytes(length, byteorder="big").decode("utf-8")


# ----------------------------------------------------------------------
# Testes rápidos de sanidade (executar: python -m protocols.elgamal)
# ----------------------------------------------------------------------
if __name__ == "__main__":
    print("=== Teste: ElGamal com grupo pequeno (p=23, q=11, g=4) ===")
    grupo = SubgroupGq(p=23, q=11, g=4)
    eg = ElGamal(grupo)

    priv, pub = eg.generate_keypair()
    print(f"Chave privada: x={priv}, chave pública: h={pub}")

    # Testa com todos os membros do grupo como mensagens
    membros = [grupo.power(grupo.g, k) for k in range(1, grupo.q)]
    for m in membros:
        c1, c2 = eg.encrypt(pub, m)
        m_dec = eg.decrypt(priv, (c1, c2))
        assert m_dec == m, f"Falha para m={m}: decifrou {m_dec}"
    print(f"Todas as {len(membros)} mensagens cifradas e decifradas corretamente.  OK")

    print("\n=== Teste: duas cifrações da mesma mensagem são diferentes (k aleatório) ===")
    m = grupo.power(grupo.g, 3)
    ct1 = eg.encrypt(pub, m)
    ct2 = eg.encrypt(pub, m)
    assert ct1 != ct2
    print(f"Mensagem m={m} cifrada duas vezes: {ct1} e {ct2} — diferentes.  OK")

    print("\n=== Teste: chave pública inválida é rejeitada ===")
    try:
        eg.encrypt(5, membros[0])  # 5 não pertence a G_11
        assert False
    except ValueError as e:
        print("Chave pública inválida rejeitada:", e)

    print("\n=== Teste: ElGamal com grupo gerado automaticamente (64 bits) ===")
    grupo_grande = SubgroupGq.generate(bits_p=64)
    eg_grande = ElGamal(grupo_grande)
    priv_g, pub_g = eg_grande.generate_keypair()

    m = grupo_grande.random_element()
    ct = eg_grande.encrypt(pub_g, m)
    m_dec = eg_grande.decrypt(priv_g, ct)
    assert m_dec == m
    print(f"Grupo de 64 bits: mensagem cifrada e decifrada com sucesso.  OK")

    print("\nTodos os testes de elgamal.py passaram.")