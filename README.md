# Criptografia — Trabalho Final

Implementação autoral de:
- **Parte I:** Diffie-Hellman e ElGamal sobre o grupo algébrico G_q (subgrupo de ordem prima q em (Z/pZ)*)
- **Parte II:** Cifra de bloco simétrica original MiniARX-64 (família ARX)

---

## Estrutura

```
crypto-trabalho/
│
├── group/
│   └── subgroup.py           # Grupo G_q: operações, gerador, verificação de membros
│
├── protocols/
│   ├── diffie_hellman.py     # Protocolo Diffie-Hellman
│   ├── elgamal.py            # Cifração e decifração ElGamal
│   └── elgamal_signature.py  # Assinatura digital ElGamal (bônus)
│
├── symmetric/
│   ├── key_schedule.py       # Geração de subchaves do MiniARX-64
│   └── miniarx.py            # Cifra de bloco ARX: cifração, decifração, modos ECB/CBC
│
├── analysis/
│   ├── avalanche.py          # Análise de efeito avalanche (plaintext e chave)
│   ├── performance.py        # Benchmarks de desempenho vs AES-128
│   └── comparison.py         # Tabela comparativa completa MiniARX-64 vs AES-128
│
├── utils/
│   └── math_utils.py         # exp_mod, inverso modular, Miller-Rabin, geração de primos
│
├── demos/
│   ├── demo_dh.py            # Demonstração Diffie-Hellman entre Alice e Bob
│   ├── demo_elgamal.py       # Demonstração ElGamal (cifração de texto)
│   └── demo_symmetric.py     # Demonstração MiniARX-64 (cifração, avalanche, CBC)
│
└── tests/
    ├── test_group.py
    ├── test_dh.py
    ├── test_elgamal.py
    ├── test_elgamal_signature.py
    └── test_symmetric.py
```

---

## Instalação

```bash
pip install pytest
```

Para comparação de desempenho com AES (opcional):

```bash
pip install cryptography
```

---

## Como rodar

> Todos os comandos devem ser executados a partir da **raiz do projeto**.

---

## Parte I — Criptografia de Chave Pública

### Diffie-Hellman

```bash
python3 -m demos.demo_dh
pytest tests/test_dh.py -v
```

### ElGamal (cifração)

```bash
python3 -m demos.demo_elgamal
pytest tests/test_elgamal.py -v
```

### Assinatura Digital ElGamal (bônus)

```bash
python3 -m protocols.elgamal_signature
pytest tests/test_elgamal_signature.py -v
```

---

## Parte II — Criptossistema Simétrico (MiniARX-64)

### Demonstração (cifração CBC, efeito avalanche, não-determinismo)

```bash
python3 -m demos.demo_symmetric
```

### Testes funcionais

```bash
pytest tests/test_symmetric.py -v
```

### Análise de efeito avalanche (10.000 amostras)

```bash
python3 -m analysis.avalanche
```

### Benchmark de desempenho

```bash
python3 -m analysis.performance
```

### Tabela comparativa completa com AES-128

```bash
python3 -m analysis.comparison
```

---

## Todos os testes de uma vez

```bash
pytest tests/ -v
```