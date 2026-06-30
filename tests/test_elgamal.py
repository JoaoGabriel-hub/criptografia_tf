"""
test_elgamal.py

Testes funcionais (pytest) para o criptossistema ElGamal
(protocols/elgamal.py).

Verifica:
    - corretude de cifração/decifração para todos os membros do grupo
    - que cifrações da mesma mensagem produzem criptogramas diferentes
    - domínio das chaves geradas
    - rejeição de entradas inválidas (mensagem fora do range, chave inválida)
    - funcionamento em grupo maior gerado automaticamente

Rodar com:
    pytest tests/test_elgamal.py -v
"""

import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import pytest

from group.subgroup import SubgroupGq
from protocols.elgamal import ElGamal


# ----------------------------------------------------------------------
# Fixtures
# ----------------------------------------------------------------------

@pytest.fixture
def grupo():
    return SubgroupGq(p=23, q=11, g=4)


@pytest.fixture
def eg(grupo):
    return ElGamal(grupo)


@pytest.fixture
def keypair(eg):
    return eg.generate_keypair()


@pytest.fixture
def grupo_maior():
    return SubgroupGq.generate(bits_p=48)


# ----------------------------------------------------------------------
# Geração de chaves
# ----------------------------------------------------------------------

def test_chave_privada_no_intervalo_valido(eg, grupo):
    for _ in range(20):
        priv, _ = eg.generate_keypair()
        assert 1 <= priv <= grupo.q - 1


def test_chave_publica_pertence_ao_grupo(eg, grupo):
    for _ in range(20):
        _, pub = eg.generate_keypair()
        assert grupo.is_member(pub)


def test_chave_publica_consistente_com_privada(eg, grupo):
    priv, pub = eg.generate_keypair()
    assert pub == grupo.power(grupo.g, priv)


# ----------------------------------------------------------------------
# Cifração / Decifração — corretude central
# ----------------------------------------------------------------------

def test_decifracao_recupera_mensagem_original(eg, keypair, grupo):
    priv, pub = keypair
    for k in range(1, grupo.q):
        m = grupo.power(grupo.g, k)
        ct = eg.encrypt(pub, m)
        assert eg.decrypt(priv, ct) == m


def test_decifracao_todos_membros_do_grupo(eg, keypair, grupo):
    priv, pub = keypair
    membros = [grupo.power(grupo.g, k) for k in range(1, grupo.q)]
    for m in membros:
        ct = eg.encrypt(pub, m)
        assert eg.decrypt(priv, ct) == m


def test_criptograma_tem_dois_componentes(eg, keypair, grupo):
    _, pub = keypair
    m = grupo.power(grupo.g, 3)
    ct = eg.encrypt(pub, m)
    c1, c2 = ct
    assert grupo.is_member(c1)
    assert 1 <= c2 <= grupo.p - 1


def test_c1_pertence_ao_grupo(eg, keypair, grupo):
    _, pub = keypair
    m = grupo.power(grupo.g, 5)
    c1, _ = eg.encrypt(pub, m)
    assert grupo.is_member(c1)


# ----------------------------------------------------------------------
# Não-determinismo: mesmo m, cifrações diferentes
# ----------------------------------------------------------------------

def test_mesma_mensagem_gera_criptogramas_diferentes(eg, keypair, grupo):
    _, pub = keypair
    m = grupo.power(grupo.g, 3)
    resultados = set()
    for _ in range(10):
        ct = eg.encrypt(pub, m)
        resultados.add(ct)
    # Com k aleatório em [1, q-1], praticamente nunca repete
    assert len(resultados) > 1


def test_mesma_mensagem_decifra_igual_em_todas_as_cifrações(eg, keypair, grupo):
    priv, pub = keypair
    m = grupo.power(grupo.g, 4)
    for _ in range(10):
        ct = eg.encrypt(pub, m)
        assert eg.decrypt(priv, ct) == m


# ----------------------------------------------------------------------
# Isolamento: chave errada não decifra
# ----------------------------------------------------------------------

def test_chave_privada_errada_nao_decifra(eg, grupo):
    priv_alice, pub_alice = eg.generate_keypair()
    priv_bob, _ = eg.generate_keypair()

    m = grupo.power(grupo.g, 5)
    ct = eg.encrypt(pub_alice, m)

    # Bob tenta decifrar com sua chave — não deve funcionar
    m_errado = eg.decrypt(priv_bob, ct)
    assert m_errado != m


# ----------------------------------------------------------------------
# Validação de entradas inválidas
# ----------------------------------------------------------------------

def test_mensagem_zero_e_rejeitada(eg, keypair):
    _, pub = keypair
    with pytest.raises(ValueError):
        eg.encrypt(pub, 0)


def test_mensagem_maior_que_p_e_rejeitada(eg, keypair, grupo):
    _, pub = keypair
    with pytest.raises(ValueError):
        eg.encrypt(pub, grupo.p)


def test_chave_publica_fora_do_grupo_e_rejeitada(eg, grupo):
    # 5 não pertence a G_11 com p=23, q=11
    m = grupo.power(grupo.g, 3)
    with pytest.raises(ValueError):
        eg.encrypt(5, m)


def test_c1_invalido_na_decifracao_e_rejeitado(eg, keypair):
    priv, _ = keypair
    with pytest.raises(ValueError):
        eg.decrypt(priv, (5, 12))  # c1=5 não pertence ao grupo


# ----------------------------------------------------------------------
# Teste em grupo maior
# ----------------------------------------------------------------------

def test_elgamal_funciona_em_grupo_grande(grupo_maior):
    eg_grande = ElGamal(grupo_maior)
    priv, pub = eg_grande.generate_keypair()

    m = grupo_maior.random_element()
    ct = eg_grande.encrypt(pub, m)
    assert eg_grande.decrypt(priv, ct) == m


def test_multiplas_mensagens_em_grupo_grande(grupo_maior):
    eg_grande = ElGamal(grupo_maior)
    priv, pub = eg_grande.generate_keypair()

    for _ in range(10):
        m = grupo_maior.random_element()
        ct = eg_grande.encrypt(pub, m)
        assert eg_grande.decrypt(priv, ct) == m


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))