# Criptografia — Trabalho Final

Implementação autoral de Diffie-Hellman e ElGamal sobre o grupo algébrico **G_q** (subgrupo de ordem prima q em (Z/pZ)*).

---

## Estrutura

```
crypto-trabalho/
│
├── group/
│   └── subgroup.py          # Grupo G_q: operações, gerador, verificação de membros
│
├── protocols/
│   ├── diffie_hellman.py    # Protocolo Diffie-Hellman
│   ├── elgamal.py           # Cifração e decifração ElGamal
│   └── elgamal_signature.py # Assinatura digital ElGamal (bônus)
│
├── utils/
│   └── math_utils.py        # exp_mod, inverso modular, Miller-Rabin, geração de primos
│
├── demos/
│   ├── demo_dh.py           # Demonstração Diffie-Hellman entre Alice e Bob
│   └── demo_elgamal.py      # Demonstração ElGamal (cifração de texto)
│
└── tests/
    ├── test_math_utils.py
    ├── test_group.py
    ├── test_dh.py
    ├── test_elgamal.py
    └── test_elgamal_signature.py
```

---

## Instalação

```bash
pip install pytest
```

---

## Como rodar

> Todos os comandos devem ser executados a partir da **raiz do projeto**.

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

### Todos os testes de uma vez

```bash
pytest tests/ -v
