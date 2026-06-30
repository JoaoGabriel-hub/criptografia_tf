"""
test_dh.py

Testes funcionais (pytest) para o protocolo Diffie-Hellman
(protocols/diffie_hellman.py).

Verifica:
    - corretude da troca de segredo (Alice e Bob chegam ao mesmo K)
    - chaves privadas e públicas dentro dos domínios esperados
    - rejeição de chaves públicas fora do grupo
    - corretude com múltiplos pares de chaves e com grupos diferentes
    - que diferentes execuções produzem segredos diferentes (chaves aleatórias)

Rodar com:
    pytest tests/test_dh.py -v
"""

import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import pytest

from group.subgroup import SubgroupGq
from protocols.diffie_hellman import DiffieHellman


# ----------------------------------------------------------------------
# Fixtures
# ----------------------------------------------------------------------

@pytest.fixture
def grupo_pequeno():
    """Grupo pequeno e determinístico, fácil de auditar manualmente."""
    return SubgroupGq(p=23, q=11, g=4)


@pytest.fixture
def dh(grupo_pequeno):
    return DiffieHellman(grupo_pequeno)


@pytest.fixture
def grupo_maior():
    """Grupo maior, gerado automaticamente, para testar em escala mais realista."""
    return SubgroupGq.generate(bits_p=48)


# ----------------------------------------------------------------------
# generate_keypair
# ----------------------------------------------------------------------

def test_chave_privada_no_intervalo_valido(dh, grupo_pequeno):
    for _ in range(20):
        priv, _ = dh.generate_keypair()
        assert 1 <= priv <= grupo_pequeno.q - 1


def test_chave_publica_pertence_ao_grupo(dh, grupo_pequeno):
    for _ in range(20):
        _, pub = dh.generate_keypair()
        assert grupo_pequeno.is_member(pub)


def test_chave_publica_consistente_com_privada(dh, grupo_pequeno):
    priv, pub = dh.generate_keypair()
    assert pub == grupo_pequeno.power(grupo_pequeno.g, priv)


def test_chamadas_sucessivas_geram_chaves_diferentes(dh):
    # Probabilisticamente, duas chamadas não devem coincidir
    pares = [dh.generate_keypair() for _ in range(10)]
    privadas = [p for p, _ in pares]
    assert len(set(privadas)) > 1  # não são todas iguais


# ----------------------------------------------------------------------
# compute_shared_secret — corretude central do protocolo
# ----------------------------------------------------------------------

def test_alice_e_bob_chegam_ao_mesmo_segredo(dh):
    alice_priv, alice_pub = dh.generate_keypair()
    bob_priv, bob_pub = dh.generate_keypair()

    segredo_alice = dh.compute_shared_secret(alice_priv, bob_pub)
    segredo_bob = dh.compute_shared_secret(bob_priv, alice_pub)

    assert segredo_alice == segredo_bob


def test_segredo_compartilhado_eh_membro_do_grupo(dh, grupo_pequeno):
    alice_priv, alice_pub = dh.generate_keypair()
    bob_priv, bob_pub = dh.generate_keypair()

    segredo = dh.compute_shared_secret(alice_priv, bob_pub)
    assert grupo_pequeno.is_member(segredo)


def test_segredo_bate_com_formula_g_elevado_ab(dh, grupo_pequeno):
    alice_priv, alice_pub = dh.generate_keypair()
    bob_priv, bob_pub = dh.generate_keypair()

    segredo = dh.compute_shared_secret(alice_priv, bob_pub)
    esperado = grupo_pequeno.power(grupo_pequeno.g, alice_priv * bob_priv)

    assert segredo == esperado


def test_multiplas_trocas_sao_consistentes(dh):
    # Roda o protocolo várias vezes seguidas com pares de chaves novos
    for _ in range(15):
        a_priv, a_pub = dh.generate_keypair()
        b_priv, b_pub = dh.generate_keypair()

        seg_a = dh.compute_shared_secret(a_priv, b_pub)
        seg_b = dh.compute_shared_secret(b_priv, a_pub)

        assert seg_a == seg_b


def test_pares_de_chaves_diferentes_dao_segredos_diferentes(dh):
    # Segredo entre (Alice, Bob) deve ser diferente do segredo entre (Alice, Carol),
    # exceto em coincidências de probabilidade desprezível
    alice_priv, alice_pub = dh.generate_keypair()
    _, bob_pub = dh.generate_keypair()
    _, carol_pub = dh.generate_keypair()

    segredo_com_bob = dh.compute_shared_secret(alice_priv, bob_pub)
    segredo_com_carol = dh.compute_shared_secret(alice_priv, carol_pub)

    assert segredo_com_bob != segredo_com_carol


# ----------------------------------------------------------------------
# Validação / robustez
# ----------------------------------------------------------------------

def test_chave_publica_fora_do_grupo_eh_rejeitada(dh):
    # 5 não pertence a G_11 no grupo p=23, q=11 (ver tests/test_group.py)
    alice_priv, _ = dh.generate_keypair()
    with pytest.raises(ValueError):
        dh.compute_shared_secret(alice_priv, 5)


def test_chave_publica_zero_eh_rejeitada(dh):
    alice_priv, _ = dh.generate_keypair()
    with pytest.raises(ValueError):
        dh.compute_shared_secret(alice_priv, 0)


# ----------------------------------------------------------------------
# Teste em grupo maior (mais realista)
# ----------------------------------------------------------------------

def test_dh_funciona_em_grupo_grande(grupo_maior):
    dh_grande = DiffieHellman(grupo_maior)

    alice_priv, alice_pub = dh_grande.generate_keypair()
    bob_priv, bob_pub = dh_grande.generate_keypair()

    segredo_alice = dh_grande.compute_shared_secret(alice_priv, bob_pub)
    segredo_bob = dh_grande.compute_shared_secret(bob_priv, alice_pub)

    assert segredo_alice == segredo_bob
    assert grupo_maior.is_member(segredo_alice)


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))