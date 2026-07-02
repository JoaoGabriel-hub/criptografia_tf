# Criptografia — Trabalho Final

Implementação autoral de:
- **Parte I:** Diffie-Hellman e ElGamal sobre o grupo algébrico G_q (subgrupo de ordem prima q em (Z/pZ)*)
- **Parte II:** Cifra de bloco simétrica original MiniARX-64 (família ARX)

Todas as implementações são autorais, sem uso de bibliotecas criptográficas externas. A biblioteca `cryptography` é usada apenas como referência de benchmark para o AES.

---

## Visão Geral das Pastas

### `utils/`
Funções matemáticas puras que sustentam todo o projeto. Não depende de nenhum outro módulo.

- **`math_utils.py`** — exponenciação modular rápida (square-and-multiply), algoritmo de Euclides estendido, inverso modular, teste de primalidade de Miller-Rabin, geração de primos aleatórios e geração de primos seguros (p = 2q + 1). Estas funções são o alicerce dos protocolos de chave pública.

---

### `group/`
Define o grupo algébrico escolhido para a Parte I: o subgrupo de ordem prima G_q dentro de (Z/pZ)*.

- **`subgroup.py`** — classe `SubgroupGq` com todos os parâmetros do grupo (p, q, g) e operações: multiplicação modular, exponenciação, inverso, verificação de membro, amostragem aleatória e geração automática de parâmetros via `generate(bits_p)`. É o núcleo reutilizado por Diffie-Hellman e ElGamal.

---

### `protocols/`
Implementações dos protocolos de chave pública, construídas sobre o grupo G_q.

- **`diffie_hellman.py`** — protocolo de troca de chaves Diffie-Hellman. Oferece geração de par de chaves (privada, pública) e cálculo do segredo compartilhado. Valida que a chave pública recebida pertence ao grupo, prevenindo ataques de subgrupo pequeno.

- **`elgamal.py`** — criptossistema ElGamal para cifração e decifração. Usa expoente efêmero aleatório a cada cifração, garantindo não-determinismo e segurança semântica IND-CPA. Inclui funções auxiliares de conversão texto ↔ inteiro para uso nas demos.

- **`elgamal_signature.py`** — assinatura digital ElGamal (bônus). Usa SHA-256 para hash da mensagem antes de assinar, suportando mensagens de qualquer tamanho. Implementa geração de par de chaves, assinatura e verificação. Inclui proteção contra reutilização do expoente efêmero k.

---

### `symmetric/`
Implementação da cifra de bloco original MiniARX-64, pertencente à família ARX (Addition-Rotation-XOR).

- **`key_schedule.py`** — geração das 16 pares de subchaves a partir de 128 bits de chave mestre. Usa constantes derivadas dos primeiros dígitos hexadecimais de π para eliminar simetrias entre rodadas e prevenir chaves fracas. Produz 32 subchaves de 32 bits totalizando 128 bytes.

- **`miniarx.py`** — núcleo do MiniARX-64: bloco de 64 bits, chave de 128 bits, 16 rodadas ARX com rotações (12, 7). Implementa cifração e decifração por bloco, além da classe `MiniARX64` com suporte a mensagens de tamanho arbitrário nos modos ECB e CBC com padding PKCS#7 e IV aleatório.

---

### `analysis/`
Ferramentas de análise de segurança e desempenho do MiniARX-64.

- **`avalanche.py`** — mede o efeito avalanche em três dimensões: variação de plaintext (10.000 amostras), variação de chave (10.000 amostras) e distribuição por bit de saída (5.000 amostras). Resultado esperado: ~50% dos bits alterados ao mudar 1 bit na entrada.

- **`performance.py`** — benchmarks de throughput (MB/s), latência por chamada (µs), tempo de geração de subchaves e pico de memória. Mede o MiniARX-64 em Python puro e o AES-128-CBC via biblioteca `cryptography` (C otimizado) para referência comparativa.

- **`comparison.py`** — consolida todos os benchmarks e análises em uma tabela comparativa completa entre MiniARX-64 e AES-128, cobrindo estrutura, desempenho, propriedades de segurança e características qualitativas.

---

### `demos/`
Scripts narrativos que demonstram o funcionamento de cada protocolo de forma didática, com saídas explicativas passo a passo.

- **`demo_dh.py`** — simula a troca de chaves entre Alice e Bob em dois cenários: grupo didático (p=23, q=11) com valores auditáveis manualmente, e grupo realista de 256 bits com medição de tempo de execução.

- **`demo_elgamal.py`** — demonstra cifração e decifração ElGamal em três cenários: grupo didático com acompanhamento das operações internas, evidência de não-determinismo (mesma mensagem cifrada 5 vezes produz criptogramas distintos) e cifração de texto real com grupo de 256 bits.

- **`demo_symmetric.py`** — demonstra o MiniARX-64 em três cenários: cifração e decifração de texto em modo CBC, visualização concreta do efeito avalanche (1 bit diferente no plaintext e seu impacto no ciphertext) e não-determinismo do modo CBC com IVs aleatórios.

---

### `tests/`
Testes funcionais automatizados com pytest, cobrindo corretude, domínio de entradas, aleatoriedade, casos de borda e rejeição de entradas inválidas.

- **`test_math_utils.py`** — testa todas as funções matemáticas isoladamente, incluindo consistência com `pow()` nativo do Python em 20 casos aleatórios.
- **`test_group.py`** — verifica os quatro axiomas de grupo (fechamento, identidade, inverso, associatividade), que o gerador percorre todos os q elementos e que a ordem de g é exatamente q.
- **`test_dh.py`** — verifica que Alice e Bob chegam ao mesmo segredo, que o segredo pertence ao grupo, que chaves inválidas são rejeitadas e que pares diferentes produzem segredos diferentes.
- **`test_elgamal.py`** — verifica corretude de cifração para todos os membros do grupo, não-determinismo das cifrações e isolamento de chaves.
- **`test_elgamal_signature.py`** — verifica corretude da assinatura, rejeição de mensagem alterada, chave errada e assinatura corrompida, além do não-determinismo por conta do k efêmero.
- **`test_symmetric.py`** — verifica corretude do MiniARX-64 em ECB e CBC para mensagens de tamanhos variados, efeito avalanche médio próximo de 50% em 1.000 amostras, propagação de erro no CBC e rejeição de parâmetros inválidos.

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