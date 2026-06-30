"""
test_elgamal_signature.py

Testes funcionais (pytest) para a Assinatura Digital ElGamal
(protocols/elgamal_signature.py).

Verifica:
    - corretude: assinar e verificar com a chave correta retorna True
    - rejeição de mensagem alterada
    - rejeição de chave pública errada
    - rejeição de assinatura corrompida
    - não-determinismo: mesma mensagem, assinaturas diferentes
    - rejeição de domínio inválido (r ou s fora dos limites)
    - funcionamento em grupo maior

Nota sobre o grupo pequeno (p=23):
    Com p=23, o espaço de hash é mod(p-1)=22 — apenas 22 valores
    possíveis. Isso torna colisões de hash frequentes para mensagens
    próximas (ex.: "msg" e "msgx" podem ter o mesmo hash mod 22).
    Por isso, os testes que verificam rejeição de mensagem alterada
    usam grupos maiores (bits_p >= 64), onde colisões são desprezíveis.

Rodar com:
    pytest tests/test_elgamal_signature.py -v
"""

import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import pytest

from group.subgroup import SubgroupGq
from protocols.elgamal_signature import ElGamalSignature


# ─────────────────────────────────────────────────────────────────────
# Fixtures
# ─────────────────────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def grupo_pequeno():
    """Grupo didático — bom para testes de corretude básica."""
    return SubgroupGq(p=23, q=11, g=4)


@pytest.fixture(scope="module")
def grupo_medio():
    """Grupo de 64 bits — suficiente para testes de hash sem colisões."""
    return SubgroupGq.generate(bits_p=64)


@pytest.fixture(scope="module")
def eg_pequeno(grupo_pequeno):
    return ElGamalSignature(grupo_pequeno)


@pytest.fixture(scope="module")
def eg_medio(grupo_medio):
    return ElGamalSignature(grupo_medio)


@pytest.fixture(scope="module")
def keypair_pequeno(eg_pequeno):
    return eg_pequeno.generate_keypair()


@pytest.fixture(scope="module")
def keypair_medio(eg_medio):
    return eg_medio.generate_keypair()


# ─────────────────────────────────────────────────────────────────────
# Geração de chaves
# ─────────────────────────────────────────────────────────────────────

def test_chave_privada_no_intervalo_valido(eg_pequeno, grupo_pequeno):
    for _ in range(20):
        priv, _ = eg_pequeno.generate_keypair()
        assert 1 <= priv <= grupo_pequeno.p - 2


def test_chave_publica_no_intervalo_valido(eg_pequeno, grupo_pequeno):
    for _ in range(20):
        _, pub = eg_pequeno.generate_keypair()
        assert 1 <= pub <= grupo_pequeno.p - 1


def test_chave_publica_consistente_com_privada(eg_pequeno, grupo_pequeno):
    from utils.math_utils import exp_mod
    priv, pub = eg_pequeno.generate_keypair()
    assert pub == exp_mod(grupo_pequeno.g, priv, grupo_pequeno.p)


# ─────────────────────────────────────────────────────────────────────
# Corretude: sign → verify com chave correta
# ─────────────────────────────────────────────────────────────────────

def test_verificacao_com_chave_correta_retorna_true(eg_pequeno, keypair_pequeno):
    priv, pub = keypair_pequeno
    msg = b"mensagem de teste"
    sig = eg_pequeno.sign(priv, msg)
    assert eg_pequeno.verify(pub, msg, sig) is True


def test_multiplas_mensagens_assinadas_corretamente(eg_medio, keypair_medio):
    priv, pub = keypair_medio
    mensagens = [b"alfa", b"beta", b"gamma", b"hello world", b"ElGamal 2025"]
    for msg in mensagens:
        sig = eg_medio.sign(priv, msg)
        assert eg_medio.verify(pub, msg, sig) is True


def test_verificacao_repete_corretamente(eg_medio, keypair_medio):
    # A mesma assinatura deve ser verificável múltiplas vezes
    priv, pub = keypair_medio
    msg = b"mensagem repetida"
    sig = eg_medio.sign(priv, msg)
    for _ in range(10):
        assert eg_medio.verify(pub, msg, sig) is True


# ─────────────────────────────────────────────────────────────────────
# Rejeição: mensagem alterada
# ─────────────────────────────────────────────────────────────────────

def test_mensagem_alterada_invalida_assinatura(eg_medio, keypair_medio):
    priv, pub = keypair_medio
    msg_original = b"mensagem original"
    sig = eg_medio.sign(priv, msg_original)
    assert eg_medio.verify(pub, b"mensagem modificada", sig) is False


def test_byte_extra_invalida_assinatura(eg_medio, keypair_medio):
    priv, pub = keypair_medio
    msg = b"mensagem"
    sig = eg_medio.sign(priv, msg)
    assert eg_medio.verify(pub, msg + b"!", sig) is False


def test_mensagem_vazia_assinada_invalida_com_outra(eg_medio, keypair_medio):
    priv, pub = keypair_medio
    sig_vazia = eg_medio.sign(priv, b"")
    assert eg_medio.verify(pub, b"nao vazia", sig_vazia) is False


# ─────────────────────────────────────────────────────────────────────
# Rejeição: chave pública errada
# ─────────────────────────────────────────────────────────────────────

def test_chave_publica_errada_invalida_assinatura(eg_medio, keypair_medio):
    priv, pub_certa = keypair_medio
    _, pub_errada = eg_medio.generate_keypair()
    msg = b"mensagem autenticada"
    sig = eg_medio.sign(priv, msg)
    assert eg_medio.verify(pub_errada, msg, sig) is False


# ─────────────────────────────────────────────────────────────────────
# Rejeição: assinatura corrompida
# ─────────────────────────────────────────────────────────────────────

def test_r_corrompido_invalida_assinatura(eg_medio, keypair_medio):
    priv, pub = keypair_medio
    msg = b"mensagem"
    r, s = eg_medio.sign(priv, msg)
    assert eg_medio.verify(pub, msg, (r + 1, s)) is False


def test_s_corrompido_invalida_assinatura(eg_medio, keypair_medio):
    priv, pub = keypair_medio
    msg = b"mensagem"
    r, s = eg_medio.sign(priv, msg)
    assert eg_medio.verify(pub, msg, (r, s + 1)) is False


def test_assinatura_trocada_entre_mensagens_invalida(eg_medio, keypair_medio):
    priv, pub = keypair_medio
    sig_m1 = eg_medio.sign(priv, b"mensagem 1")
    assert eg_medio.verify(pub, b"mensagem 2", sig_m1) is False


# ─────────────────────────────────────────────────────────────────────
# Verificação de domínio
# ─────────────────────────────────────────────────────────────────────

def test_r_zero_invalido(eg_pequeno, keypair_pequeno):
    _, pub = keypair_pequeno
    assert eg_pequeno.verify(pub, b"msg", (0, 5)) is False


def test_s_zero_invalido(eg_pequeno, keypair_pequeno):
    _, pub = keypair_pequeno
    assert eg_pequeno.verify(pub, b"msg", (5, 0)) is False


def test_r_maior_que_p_invalido(eg_pequeno, keypair_pequeno, grupo_pequeno):
    _, pub = keypair_pequeno
    assert eg_pequeno.verify(pub, b"msg", (grupo_pequeno.p, 5)) is False


# ─────────────────────────────────────────────────────────────────────
# Não-determinismo
# ─────────────────────────────────────────────────────────────────────

def test_mesma_mensagem_gera_assinaturas_diferentes(eg_pequeno, keypair_pequeno):
    priv, pub = keypair_pequeno
    msg = b"mesma mensagem"
    sigs = set(eg_pequeno.sign(priv, msg) for _ in range(10))
    assert len(sigs) > 1  # assinaturas diferentes pelo k aleatório


def test_todas_assinaturas_diferentes_sao_validas(eg_pequeno, keypair_pequeno):
    priv, pub = keypair_pequeno
    msg = b"mesma mensagem"
    for _ in range(10):
        sig = eg_pequeno.sign(priv, msg)
        assert eg_pequeno.verify(pub, msg, sig) is True


# ─────────────────────────────────────────────────────────────────────
# Grupo maior
# ─────────────────────────────────────────────────────────────────────

def test_assinatura_funciona_em_grupo_de_128_bits():
    grupo = SubgroupGq.generate(bits_p=128)
    eg = ElGamalSignature(grupo)
    priv, pub = eg.generate_keypair()
    msg = b"Criptografia de chave publica - ElGamal"
    sig = eg.sign(priv, msg)
    assert eg.verify(pub, msg, sig) is True
    assert eg.verify(pub, b"mensagem diferente", sig) is False


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))