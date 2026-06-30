"""
math_utils.py

Funções matemáticas puras usadas pelos protocolos criptográficos.
Nenhuma dependência de bibliotecas de criptografia — apenas aritmética
de inteiros, implementada de forma autoral.

Funções:
    exp_mod(base, exp, mod)        -> exponenciação modular rápida
    extended_gcd(a, b)             -> algoritmo de Euclides estendido
    mod_inverse(a, mod)            -> inverso multiplicativo modular
    is_prime(n, k)                 -> teste de primalidade de Miller-Rabin
    random_prime(bits)             -> gera primo aleatório com `bits` bits
    generate_safe_prime(bits)      -> gera primo seguro p = 2q + 1
"""

import random


def exp_mod(base: int, exp: int, mod: int) -> int:
    """
    Calcula (base ** exp) % mod usando exponenciação rápida
    (square-and-multiply), em O(log exp) multiplicações modulares.

    Funciona mesmo para expoentes muito grandes, sem nunca calcular
    base ** exp por extenso (o que seria inviável para números grandes).
    """
    if mod == 1:
        return 0

    resultado = 1
    base = base % mod

    while exp > 0:
        # Se o bit menos significativo de exp é 1, multiplica no resultado
        if exp & 1:
            resultado = (resultado * base) % mod
        # Eleva a base ao quadrado e desce um bit no expoente
        base = (base * base) % mod
        exp >>= 1

    return resultado


def extended_gcd(a: int, b: int):
    """
    Algoritmo de Euclides estendido.

    Retorna a tripla (g, x, y) tal que:
        g = mdc(a, b)
        a*x + b*y = g

    Usado para calcular o inverso modular.
    """
    if a == 0:
        return (b, 0, 1)

    g, x1, y1 = extended_gcd(b % a, a)
    x = y1 - (b // a) * x1
    y = x1

    return (g, x, y)


def mod_inverse(a: int, mod: int) -> int:
    """
    Calcula o inverso multiplicativo de `a` módulo `mod`, isto é,
    o inteiro a_inv tal que (a * a_inv) % mod == 1.

    Levanta ValueError se o inverso não existir (mdc(a, mod) != 1).
    """
    a = a % mod
    g, x, _ = extended_gcd(a, mod)

    if g != 1:
        raise ValueError(f"Inverso modular não existe para a={a}, mod={mod} (mdc={g})")

    return x % mod


def is_prime(n: int, k: int = 40) -> bool:
    """
    Teste de primalidade probabilístico de Miller-Rabin.

    Parâmetros:
        n: número a testar
        k: número de rodadas de teste (quanto maior, menor a chance de
           falso positivo; k=40 dá probabilidade de erro ~ 4^-40,
           desprezível na prática)

    Retorna True se n é (muito provavelmente) primo, False se é composto.
    """
    if n < 2:
        return False
    if n in (2, 3):
        return True
    if n % 2 == 0:
        return False

    # Escreve n - 1 como d * 2^r, com d ímpar
    d = n - 1
    r = 0
    while d % 2 == 0:
        d //= 2
        r += 1

    # Repete o teste k vezes com bases aleatórias diferentes
    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = exp_mod(a, d, n)

        if x == 1 or x == n - 1:
            continue  # essa rodada não detectou composição; tenta outra base

        composto = True
        for _ in range(r - 1):
            x = exp_mod(x, 2, n)
            if x == n - 1:
                composto = False
                break

        if composto:
            return False  # n é definitivamente composto

    return True  # n passou em todas as rodadas: provavelmente primo


def random_prime(bits: int) -> int:
    """
    Gera um número primo aleatório com exatamente `bits` bits
    (ou seja, no intervalo [2^(bits-1), 2^bits - 1]).
    """
    while True:
        # Garante que o número tem exatamente `bits` bits:
        # fixa o bit mais significativo e o menos significativo (ímpar)
        candidato = random.getrandbits(bits) | (1 << (bits - 1)) | 1

        if is_prime(candidato):
            return candidato


def generate_safe_prime(bits: int):
    """
    Gera um "primo seguro" p = 2*q + 1, onde tanto p quanto q são primos.

    Esse formato é o ideal para o grupo G_q usado no trabalho: o
    subgrupo de ordem prima q de (Z/pZ)* terá o maior tamanho possível
    relativo a p, sem outros fatores pequenos que enfraqueçam o grupo
    (resistência ao ataque de Pohlig-Hellman).

    Parâmetros:
        bits: tamanho em bits do primo p resultante

    Retorna:
        (p, q): tupla de inteiros, ambos primos, com p = 2*q + 1
    """
    while True:
        # q tem (bits - 1) bits, de forma que p = 2q+1 tenha `bits` bits
        q = random_prime(bits - 1)
        p = 2 * q + 1

        if is_prime(p):
            return p, q


# ----------------------------------------------------------------------
# Testes rápidos de sanidade (executar diretamente: python math_utils.py)
# ----------------------------------------------------------------------
if __name__ == "__main__":
    print("=== Teste: exp_mod ===")
    # 4^13 mod 497 = 445 (exemplo clássico de verificação)
    assert exp_mod(4, 13, 497) == 445
    print("4^13 mod 497 =", exp_mod(4, 13, 497), "(esperado: 445)  OK")

    print("\n=== Teste: extended_gcd ===")
    g, x, y = extended_gcd(35, 15)
    assert g == 5
    assert 35 * x + 15 * y == g
    print(f"mdc(35,15)={g}, x={x}, y={y}, verificação: 35*{x} + 15*{y} = {35*x+15*y}  OK")

    print("\n=== Teste: mod_inverse ===")
    inv = mod_inverse(3, 11)
    assert (3 * inv) % 11 == 1
    print("inverso de 3 mod 11 =", inv, "-> 3 * inv mod 11 =", (3 * inv) % 11, " OK")

    print("\n=== Teste: is_prime ===")
    assert is_prime(7919) is True       # primo conhecido
    assert is_prime(7920) is False      # composto (7920 = 2^4 * 3^2 * 5 * 11)
    assert is_prime(23) is True
    assert is_prime(1) is False
    print("7919 é primo:", is_prime(7919), "(esperado True)")
    print("7920 é primo:", is_prime(7920), "(esperado False)")
    print("OK")

    print("\n=== Teste: random_prime ===")
    p = random_prime(16)
    assert is_prime(p)
    assert p.bit_length() == 16
    print(f"Primo aleatório de 16 bits gerado: {p} (bit_length={p.bit_length()})  OK")

    print("\n=== Teste: generate_safe_prime ===")
    p, q = generate_safe_prime(16)
    assert is_prime(p) and is_prime(q)
    assert p == 2 * q + 1
    print(f"Primo seguro gerado: p={p}, q={q}, verificação p == 2q+1: {p == 2*q+1}  OK")

    print("\nTodos os testes de math_utils.py passaram.")