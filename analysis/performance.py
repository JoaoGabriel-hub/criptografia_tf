"""
performance.py

Análise de desempenho do MiniARX-64 e comparação com AES-128.

Métricas medidas:
    - Throughput de cifração (MB/s)
    - Throughput de decifração (MB/s)
    - Latência por bloco (µs)
    - Consumo de memória (subchaves em bytes)
    - Tempo de geração de subchaves (µs)

O AES é medido via módulo `cryptography` (implementação em C otimizada),
servindo como baseline de referência industrial.
O MiniARX-64 é medido via implementação Python pura deste projeto.

Nota: a comparação de throughput é intrinsecamente desfavorável ao
MiniARX-64 em Python contra AES em C. O que importa para o trabalho
é a comparação de ESTRUTURA e PROPRIEDADES, não de velocidade bruta
de implementações em linguagens diferentes.
"""

import time
import os
import sys
import tracemalloc

from symmetric.miniarx import MiniARX64, encrypt_block, BLOCK_SIZE, KEY_SIZE
from symmetric.key_schedule import generate_subkeys


# ─────────────────────────────────────────────────────────────────────
# Utilitários de medição
# ─────────────────────────────────────────────────────────────────────

def _throughput(fn, data: bytes, warmup: int = 3, rounds: int = 10) -> dict:
    """
    Mede o throughput de uma função de cifração/decifração.

    Parâmetros:
        fn     : callable que recebe bytes e retorna bytes
        data   : dados de entrada
        warmup : número de execuções de aquecimento (descartadas)
        rounds : número de execuções medidas

    Retorna dict com:
        throughput_mbs : MB/s médio
        latency_us     : latência média por chamada em µs
        total_bytes    : bytes processados por chamada
    """
    for _ in range(warmup):
        fn(data)

    times = []
    for _ in range(rounds):
        t0 = time.perf_counter()
        fn(data)
        times.append(time.perf_counter() - t0)

    avg = sum(times) / len(times)
    return {
        "throughput_mbs": len(data) / avg / 1e6,
        "latency_us"    : avg * 1e6,
        "total_bytes"   : len(data),
    }


# ─────────────────────────────────────────────────────────────────────
# Benchmark MiniARX-64
# ─────────────────────────────────────────────────────────────────────

def benchmark_miniarx(data_size_kb: int = 64) -> dict:
    """
    Mede o desempenho do MiniARX-64 em modo CBC.

    Parâmetros:
        data_size_kb: tamanho dos dados de teste em KB

    Retorna dict com métricas de cifração e decifração.
    """
    key   = os.urandom(KEY_SIZE)
    data  = os.urandom(data_size_kb * 1024)
    iv    = bytes(BLOCK_SIZE)
    cipher = MiniARX64(key)

    # Mede tempo de geração de subchaves
    t0 = time.perf_counter()
    for _ in range(1000):
        generate_subkeys(key)
    keygen_us = (time.perf_counter() - t0) / 1000 * 1e6

    # Throughput de cifração
    ct = cipher.encrypt_cbc(data, iv=iv)
    enc_stats = _throughput(lambda d: cipher.encrypt_cbc(d, iv=iv), data)

    # Throughput de decifração
    dec_stats = _throughput(lambda c: cipher.decrypt_cbc(c), ct)

    # Memória das subchaves
    subkeys = generate_subkeys(key)
    # 16 pares de 32 bits = 16 * 2 * 4 bytes
    subkey_bytes = len(subkeys) * 2 * 4

    return {
        "cipher"          : "MiniARX-64",
        "block_bits"      : 64,
        "key_bits"        : 128,
        "rounds"          : 16,
        "keygen_us"       : keygen_us,
        "subkey_bytes"    : subkey_bytes,
        "enc_throughput"  : enc_stats["throughput_mbs"],
        "enc_latency_us"  : enc_stats["latency_us"],
        "dec_throughput"  : dec_stats["throughput_mbs"],
        "dec_latency_us"  : dec_stats["latency_us"],
        "data_size_kb"    : data_size_kb,
    }


# ─────────────────────────────────────────────────────────────────────
# Benchmark AES-128 (referência)
# ─────────────────────────────────────────────────────────────────────

def benchmark_aes(data_size_kb: int = 64) -> dict:
    """
    Mede o desempenho do AES-128-CBC via biblioteca `cryptography`.

    Retorna o mesmo formato de dict que benchmark_miniarx().
    """
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.backends import default_backend
    except ImportError:
        return {"cipher": "AES-128 (não disponível — instale: pip install cryptography)"}

    key  = os.urandom(16)   # AES-128
    iv   = os.urandom(16)   # AES block = 128 bits
    data = os.urandom(data_size_kb * 1024)

    def aes_encrypt(d):
        from cryptography.hazmat.primitives import padding as aes_padding
        padder = aes_padding.PKCS7(128).padder()
        padded = padder.update(d) + padder.finalize()
        c = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        enc = c.encryptor()
        return enc.update(padded) + enc.finalize()

    ct = aes_encrypt(data)

    def aes_decrypt(c):
        from cryptography.hazmat.primitives import padding as aes_padding
        ci = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        dec = ci.decryptor()
        padded = dec.update(c) + dec.finalize()
        unpadder = aes_padding.PKCS7(128).unpadder()
        return unpadder.update(padded) + unpadder.finalize()

    # Tempo de key schedule AES
    t0 = time.perf_counter()
    for _ in range(1000):
        Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    keygen_us = (time.perf_counter() - t0) / 1000 * 1e6

    enc_stats = _throughput(aes_encrypt, data)
    dec_stats = _throughput(aes_decrypt, ct)

    return {
        "cipher"         : "AES-128-CBC",
        "block_bits"     : 128,
        "key_bits"       : 128,
        "rounds"         : 10,
        "keygen_us"      : keygen_us,
        "subkey_bytes"   : 176,   # AES-128: 11 round keys × 16 bytes
        "enc_throughput" : enc_stats["throughput_mbs"],
        "enc_latency_us" : enc_stats["latency_us"],
        "dec_throughput" : dec_stats["throughput_mbs"],
        "dec_latency_us" : dec_stats["latency_us"],
        "data_size_kb"   : data_size_kb,
    }


# ─────────────────────────────────────────────────────────────────────
# Análise de memória
# ─────────────────────────────────────────────────────────────────────

def memory_usage_miniarx(data_size_kb: int = 64) -> dict:
    """
    Mede o uso de memória durante cifração com o MiniARX-64
    usando tracemalloc.
    """
    key  = os.urandom(KEY_SIZE)
    data = os.urandom(data_size_kb * 1024)
    iv   = bytes(BLOCK_SIZE)

    tracemalloc.start()
    cipher = MiniARX64(key)
    cipher.encrypt_cbc(data, iv=iv)
    current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    return {
        "current_kb": current / 1024,
        "peak_kb"   : peak / 1024,
    }


# ─────────────────────────────────────────────────────────────────────
# Execução direta
# ─────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    DATA_KB = 64

    print("=" * 60)
    print("ANÁLISE DE DESEMPENHO")
    print(f"Dados de teste: {DATA_KB} KB")
    print("=" * 60)

    print("\n[MiniARX-64]")
    m = benchmark_miniarx(DATA_KB)
    print(f"  Tamanho de bloco         : {m['block_bits']} bits")
    print(f"  Tamanho de chave         : {m['key_bits']} bits")
    print(f"  Número de rodadas        : {m['rounds']}")
    print(f"  Geração de subchaves     : {m['keygen_us']:.2f} µs")
    print(f"  Subchaves (memória)      : {m['subkey_bytes']} bytes")
    print(f"  Throughput (cifração)    : {m['enc_throughput']:.4f} MB/s")
    print(f"  Throughput (decifração)  : {m['dec_throughput']:.4f} MB/s")
    print(f"  Latência/chamada (enc)   : {m['enc_latency_us']:.2f} µs")
    print(f"  Latência/chamada (dec)   : {m['dec_latency_us']:.2f} µs")

    print("\n[AES-128-CBC]")
    a = benchmark_aes(DATA_KB)
    if "não disponível" in a.get("cipher", ""):
        print(f"  {a['cipher']}")
    else:
        print(f"  Tamanho de bloco         : {a['block_bits']} bits")
        print(f"  Tamanho de chave         : {a['key_bits']} bits")
        print(f"  Número de rodadas        : {a['rounds']}")
        print(f"  Geração de subchaves     : {a['keygen_us']:.2f} µs")
        print(f"  Subchaves (memória)      : {a['subkey_bytes']} bytes")
        print(f"  Throughput (cifração)    : {a['enc_throughput']:.4f} MB/s")
        print(f"  Throughput (decifração)  : {a['dec_throughput']:.4f} MB/s")
        print(f"  Latência/chamada (enc)   : {a['enc_latency_us']:.2f} µs")
        print(f"  Latência/chamada (dec)   : {a['dec_latency_us']:.2f} µs")

    print("\n[Memória — MiniARX-64]")
    mem = memory_usage_miniarx(DATA_KB)
    print(f"  Uso atual  : {mem['current_kb']:.2f} KB")
    print(f"  Pico de uso: {mem['peak_kb']:.2f} KB")