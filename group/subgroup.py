"""
subgroup.py

Implementação do grupo algébrico G_q: o subgrupo de ordem prima q
dentro de (Z/pZ)*, com p e q primos tais que q | (p-1).

Este é o grupo escolhido para o trabalho (ver relatório, Parte I,
Seção 1). Toda a aritmética de Diffie-Hellman e ElGamal é construída
sobre os métodos desta classe.

Definição:
    G_q = { a em (Z/pZ)* | a^q ≡ 1 (mod p) }

A operação é a multiplicação modulo p, herdada de (Z/pZ)*.
"""

import random

from utils.math_utils import exp_mod, mod_inverse, is_prime


class SubgroupGq:
    """
    Representa o grupo G_q, subgrupo de ordem prima q de (Z/pZ)*.

    Atributos públicos:
        p (int): primo "grande", módulo da aritmética
        q (int): primo que divide (p - 1); é a ordem do grupo G_q
        g (int): elemento gerador de G_q (ordem multiplicativa exatamente q)
    """

    def __init__(self, p: int, q: int, g: int = None):
        """
        Constrói o grupo G_q a partir de parâmetros já escolhidos.

        Parâmetros:
            p: primo tal que q | (p - 1)
            q: primo, ordem do subgrupo
            g: gerador de G_q (opcional). Se None, um gerador válido
               é encontrado automaticamente via find_generator().

        Levanta ValueError se os parâmetros não satisfizerem as
        condições matemáticas exigidas (p e q primos, q | (p-1),
        e g de fato pertencente a G_q quando fornecido).
        """
        if not is_prime(p):
            raise ValueError(f"p={p} não é primo")
        if not is_prime(q):
            raise ValueError(f"q={q} não é primo")
        if (p - 1) % q != 0:
            raise ValueError(f"q={q} não divide (p-1)={p-1}; condição q | (p-1) é obrigatória")

        self.p = p
        self.q = q

        if g is None:
            self.g = self.find_generator()
        else:
            if not self.is_member(g) or g == 1:
                raise ValueError(f"g={g} não é um gerador válido de G_{q}")
            self.g = g

    # ------------------------------------------------------------------
    # Construção do gerador
    # ------------------------------------------------------------------

    def find_generator(self) -> int:
        """
        Encontra um elemento gerador de G_q.

        Algoritmo: escolhe h aleatório em (Z/pZ)*, calcula
            g = h^((p-1)/q) mod p
        Se g != 1, g é gerador de G_q (pois G_q tem ordem prima q,
        logo todo elemento != 1 tem ordem exatamente q).

        Retorna:
            int: um gerador g de G_q
        """
        expoente = (self.p - 1) // self.q

        while True:
            h = random.randrange(2, self.p - 1)
            g = exp_mod(h, expoente, self.p)

            if g != 1:
                return g
            # g == 1 é raro (acontece só se h já estava em um subgrupo
            # "incompatível"); nesse caso tenta outro h

    # ------------------------------------------------------------------
    # Operações do grupo
    # ------------------------------------------------------------------

    def operate(self, a: int, b: int) -> int:
        """
        Operação do grupo: multiplicação modulo p.

            a . b = (a * b) mod p
        """
        return (a * b) % self.p

    def power(self, a: int, n: int) -> int:
        """
        Exponenciação no grupo: a^n mod p.

        Delega para exp_mod (square-and-multiply), de utils/math_utils.py.
        É a operação central usada em Diffie-Hellman e ElGamal.
        """
        return exp_mod(a, n, self.p)

    def inverse(self, a: int) -> int:
        """
        Inverso multiplicativo de a em G_q (e, de fato, em (Z/pZ)* também).

        Calculado via algoritmo de Euclides estendido, em utils/math_utils.py.
        """
        return mod_inverse(a, self.p)

    # ------------------------------------------------------------------
    # Verificações e amostragem
    # ------------------------------------------------------------------

    def is_member(self, a: int) -> bool:
        """
        Verifica se a pertence a G_q, isto é, se a^q ≡ 1 (mod p).
        """
        if a % self.p == 0:
            return False  # zero nunca pertence a um grupo multiplicativo
        return exp_mod(a, self.q, self.p) == 1

    def random_element(self) -> int:
        """
        Sorteia um expoente aleatório k em [1, q-1] e retorna g^k mod p,
        um elemento aleatório (não-identidade) de G_q.

        Usado para gerar chaves privadas em DH e ElGamal: a chave
        privada é, na prática, o próprio expoente k sorteado aqui
        (ver protocols/diffie_hellman.py e protocols/elgamal.py).
        """
        k = random.randrange(1, self.q)
        return self.power(self.g, k)

    def random_exponent(self) -> int:
        """
        Sorteia um inteiro aleatório em [1, q-1], adequado para uso
        como chave privada / expoente secreto em DH e ElGamal.

        Diferente de random_element(): aqui o retorno é o EXPOENTE k,
        não o elemento g^k do grupo.
        """
        return random.randrange(1, self.q)

    # ------------------------------------------------------------------
    # Geração automática de parâmetros do zero
    # ------------------------------------------------------------------

    @classmethod
    def generate(cls, bits_p: int = 256):
        """
        Gera um grupo G_q inteiramente do zero: escolhe p e q primos
        com q | (p-1) (usando primo seguro p = 2q+1) e encontra um
        gerador g.

        Parâmetros:
            bits_p: tamanho em bits do primo p

        Retorna:
            SubgroupGq: instância pronta para uso, com p, q, g definidos
        """
        # Import local para evitar import circular desnecessário
        from utils.math_utils import generate_safe_prime

        p, q = generate_safe_prime(bits_p)
        return cls(p, q)

    # ------------------------------------------------------------------
    # Representação textual (útil para debug e demos)
    # ------------------------------------------------------------------

    def __repr__(self):
        return f"SubgroupGq(p={self.p}, q={self.q}, g={self.g})"

    def __str__(self):
        return (
            f"Grupo G_{self.q} ⊂ (Z/{self.p}Z)*\n"
            f"  p (módulo)        = {self.p}\n"
            f"  q (ordem do grupo) = {self.q}\n"
            f"  g (gerador)        = {self.g}"
        )


# ----------------------------------------------------------------------
# Testes rápidos de sanidade (executar diretamente: python group/subgroup.py)
# ----------------------------------------------------------------------
if __name__ == "__main__":
    print("=== Teste: construção manual com p=23, q=11 ===")
    grupo = SubgroupGq(p=23, q=11, g=4)
    print(grupo)
    assert grupo.is_member(4)
    assert grupo.power(4, 11) == 1
    print("g=4 pertence a G_11:", grupo.is_member(4))
    print("g^11 mod p =", grupo.power(4, 11), "(esperado: 1)")

    print("\n=== Teste: G_q tem exatamente q elementos ===")
    elementos = set()
    for k in range(grupo.q):
        elementos.add(grupo.power(grupo.g, k))
    assert len(elementos) == grupo.q
    print(f"Número de elementos distintos gerados por g: {len(elementos)} (esperado: {grupo.q})")
    print("Elementos:", sorted(elementos))

    print("\n=== Teste: operate (fechamento) ===")
    a, b = grupo.power(grupo.g, 3), grupo.power(grupo.g, 5)
    c = grupo.operate(a, b)
    assert grupo.is_member(c)
    print(f"a={a}, b={b}, a.b mod p = {c}, pertence a G_q: {grupo.is_member(c)}")

    print("\n=== Teste: inverse ===")
    a = grupo.power(grupo.g, 7)
    a_inv = grupo.inverse(a)
    assert grupo.operate(a, a_inv) == 1
    print(f"a={a}, inverso={a_inv}, a . a_inv mod p = {grupo.operate(a, a_inv)} (esperado: 1)")

    print("\n=== Teste: random_element sempre pertence ao grupo ===")
    for _ in range(10):
        elem = grupo.random_element()
        assert grupo.is_member(elem)
    print("10 elementos aleatórios gerados, todos pertencem a G_q.  OK")

    print("\n=== Teste: find_generator sempre encontra gerador válido ===")
    for _ in range(5):
        g_novo = grupo.find_generator()
        ordem_elementos = set(grupo.power(g_novo, k) for k in range(grupo.q))
        assert len(ordem_elementos) == grupo.q
    print("5 geradores encontrados, todos com ordem q.  OK")

    print("\n=== Teste: construção rejeita parâmetros inválidos ===")
    try:
        SubgroupGq(p=22, q=11)  # 22 não é primo
        assert False, "deveria ter levantado ValueError"
    except ValueError as e:
        print("p não-primo corretamente rejeitado:", e)

    try:
        SubgroupGq(p=23, q=5)  # 5 não divide 22
        assert False, "deveria ter levantado ValueError"
    except ValueError as e:
        print("q que não divide (p-1) corretamente rejeitado:", e)

    print("\n=== Teste: generate() cria grupo válido do zero ===")
    grupo_gerado = SubgroupGq.generate(bits_p=24)
    print(grupo_gerado)
    assert is_prime(grupo_gerado.p)
    assert is_prime(grupo_gerado.q)
    assert (grupo_gerado.p - 1) % grupo_gerado.q == 0
    assert grupo_gerado.is_member(grupo_gerado.g)
    print("Grupo gerado automaticamente é válido.  OK")

    print("\nTodos os testes de subgroup.py passaram.")