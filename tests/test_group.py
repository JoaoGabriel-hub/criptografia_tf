"""
test_group.py

Testes funcionais (pytest) para o grupo algébrico G_q (group/subgroup.py).

Verifica:
    - axiomas de grupo (fechamento, identidade, inverso, associatividade)
    - que o gerador g realmente percorre todos os q elementos do grupo
    - que a ordem de g é exatamente q (nem menor, nem maior)
    - validação de parâmetros inválidos
    - geração automática de parâmetros via generate()

Rodar com:
    pytest tests/test_group.py -v
"""

import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import pytest

from group.subgroup import SubgroupGq
from utils.math_utils import is_prime


# ----------------------------------------------------------------------
# Fixture: grupo pequeno e conhecido, fácil de verificar manualmente
# ----------------------------------------------------------------------

@pytest.fixture
def grupo():
    """G_11 dentro de (Z/23Z)*, com gerador fixo g=4 (calculado à mão no relatório)."""
    return SubgroupGq(p=23, q=11, g=4)


@pytest.fixture
def grupo_sem_gerador_fixo():
    """Mesmo grupo, mas deixando find_generator() escolher g automaticamente."""
    return SubgroupGq(p=23, q=11)


# ----------------------------------------------------------------------
# Construção e validação de parâmetros
# ----------------------------------------------------------------------

def test_construcao_valida(grupo):
    assert grupo.p == 23
    assert grupo.q == 11
    assert grupo.g == 4


def test_p_nao_primo_levanta_erro():
    with pytest.raises(ValueError):
        SubgroupGq(p=22, q=11)  # 22 não é primo


def test_q_nao_primo_levanta_erro():
    with pytest.raises(ValueError):
        SubgroupGq(p=23, q=10)  # 10 não é primo


def test_q_nao_divide_p_menos_1_levanta_erro():
    with pytest.raises(ValueError):
        SubgroupGq(p=23, q=5)  # 5 não divide 22


def test_gerador_invalido_levanta_erro():
    with pytest.raises(ValueError):
        SubgroupGq(p=23, q=11, g=5)  # 5 não pertence a G_11 (verificar: 5^11 mod 23 != 1)


def test_gerador_eh_identidade_levanta_erro():
    with pytest.raises(ValueError):
        SubgroupGq(p=23, q=11, g=1)  # 1 é elemento neutro, não gerador válido


def test_construcao_sem_gerador_encontra_gerador_valido(grupo_sem_gerador_fixo):
    g = grupo_sem_gerador_fixo.g
    assert g != 1
    assert grupo_sem_gerador_fixo.is_member(g)


# ----------------------------------------------------------------------
# Axiomas de grupo
# ----------------------------------------------------------------------

def test_fechamento(grupo):
    # O produto de dois elementos do grupo deve permanecer no grupo
    elementos = [grupo.power(grupo.g, k) for k in range(grupo.q)]
    for a in elementos:
        for b in elementos:
            c = grupo.operate(a, b)
            assert grupo.is_member(c), f"{a} . {b} = {c} não pertence ao grupo"


def test_elemento_identidade(grupo):
    # 1 deve ser o elemento neutro: a . 1 = a para todo a do grupo
    elementos = [grupo.power(grupo.g, k) for k in range(grupo.q)]
    for a in elementos:
        assert grupo.operate(a, 1) == a
        assert grupo.operate(1, a) == a


def test_inverso_de_cada_elemento(grupo):
    # Todo elemento deve ter inverso dentro do grupo, com a . a^-1 = 1
    elementos = [grupo.power(grupo.g, k) for k in range(grupo.q)]
    for a in elementos:
        a_inv = grupo.inverse(a)
        assert grupo.operate(a, a_inv) == 1
        assert grupo.is_member(a_inv)


def test_associatividade(grupo):
    a = grupo.power(grupo.g, 2)
    b = grupo.power(grupo.g, 5)
    c = grupo.power(grupo.g, 7)

    lado_esquerdo = grupo.operate(grupo.operate(a, b), c)
    lado_direito = grupo.operate(a, grupo.operate(b, c))

    assert lado_esquerdo == lado_direito


def test_comutatividade(grupo):
    a = grupo.power(grupo.g, 3)
    b = grupo.power(grupo.g, 8)
    assert grupo.operate(a, b) == grupo.operate(b, a)


# ----------------------------------------------------------------------
# Propriedades do gerador
# ----------------------------------------------------------------------

def test_gerador_produz_todos_os_q_elementos(grupo):
    # g^0, g^1, ..., g^(q-1) devem ser todos distintos e cobrir o grupo inteiro
    elementos = set(grupo.power(grupo.g, k) for k in range(grupo.q))
    assert len(elementos) == grupo.q


def test_ordem_do_gerador_eh_exatamente_q(grupo):
    # g^q deve ser 1 (fecha o ciclo)
    assert grupo.power(grupo.g, grupo.q) == 1

    # Para nenhum k < q (exceto k=0, trivial) deveria já dar 1, pois q é primo:
    # todo elemento não-identidade tem ordem exatamente q
    for k in range(1, grupo.q):
        assert grupo.power(grupo.g, k) != 1


def test_todo_elemento_nao_identidade_e_gerador(grupo):
    # Propriedade especial de grupos de ordem prima: TODO elemento != 1 gera o grupo todo
    elementos = [grupo.power(grupo.g, k) for k in range(1, grupo.q)]

    for candidato in elementos:
        ciclo = set(grupo.power(candidato, k) for k in range(grupo.q))
        assert len(ciclo) == grupo.q, f"{candidato} não gera o grupo inteiro"


def test_membros_satisfazem_a_elevado_q_igual_1(grupo):
    for k in range(grupo.q):
        a = grupo.power(grupo.g, k)
        assert grupo.power(a, grupo.q) == 1


# ----------------------------------------------------------------------
# is_member
# ----------------------------------------------------------------------

def test_is_member_aceita_elementos_do_grupo(grupo):
    for k in range(grupo.q):
        a = grupo.power(grupo.g, k)
        assert grupo.is_member(a) is True


def test_is_member_rejeita_zero(grupo):
    assert grupo.is_member(0) is False


def test_is_member_rejeita_nao_membro():
    # No exemplo p=23, q=11: o elemento 5 não pertence a G_11
    # (5^11 mod 23 == 22, não 1 — pode-se conferir manualmente)
    grupo_teste = SubgroupGq(p=23, q=11, g=4)
    assert grupo_teste.is_member(5) is False


# ----------------------------------------------------------------------
# random_element / random_exponent
# ----------------------------------------------------------------------

def test_random_element_sempre_pertence_ao_grupo(grupo):
    for _ in range(30):
        elem = grupo.random_element()
        assert grupo.is_member(elem)


def test_random_exponent_esta_no_intervalo_valido(grupo):
    for _ in range(30):
        k = grupo.random_exponent()
        assert 1 <= k <= grupo.q - 1


# ----------------------------------------------------------------------
# find_generator
# ----------------------------------------------------------------------

def test_find_generator_retorna_gerador_valido(grupo):
    for _ in range(10):
        g_novo = grupo.find_generator()
        assert g_novo != 1
        ciclo = set(grupo.power(g_novo, k) for k in range(grupo.q))
        assert len(ciclo) == grupo.q


# ----------------------------------------------------------------------
# generate() — construção automática de parâmetros
# ----------------------------------------------------------------------

def test_generate_cria_grupo_valido():
    g = SubgroupGq.generate(bits_p=24)
    assert is_prime(g.p)
    assert is_prime(g.q)
    assert (g.p - 1) % g.q == 0
    assert g.is_member(g.g)
    assert g.g != 1


def test_generate_grupo_passa_nos_axiomas():
    # Roda uma verificação rápida de fechamento sobre um grupo gerado do zero
    g = SubgroupGq.generate(bits_p=20)
    a = g.random_element()
    b = g.random_element()
    c = g.operate(a, b)
    assert g.is_member(c)


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))