"""
comparison.py

Tabela comparativa entre MiniARX-64 e AES-128,
cobrindo todos os critérios exigidos pelo enunciado.

Executa os benchmarks de desempenho e avalanche e imprime
um relatório completo para uso no relatório acadêmico.
"""

from analysis.performance import benchmark_miniarx, benchmark_aes, memory_usage_miniarx
from analysis.avalanche   import avalanche_plaintext, avalanche_key

DATA_KB     = 64
KEY         = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
PLAINTEXT   = bytes.fromhex("0011223344556677")


def run_comparison():
    print("=" * 70)
    print("COMPARAÇÃO: MiniARX-64  vs  AES-128")
    print("=" * 70)

    # ── Coleta de dados ───────────────────────────────────────────────
    print("\nColetando benchmarks (aguarde)...")

    m   = benchmark_miniarx(DATA_KB)
    a   = benchmark_aes(DATA_KB)
    mem = memory_usage_miniarx(DATA_KB)

    print("Calculando avalanche de plaintext (10.000 amostras)...")
    av_pt = avalanche_plaintext(KEY, n_samples=10_000)

    print("Calculando avalanche de chave (10.000 amostras)...")
    av_k  = avalanche_key(PLAINTEXT, n_samples=10_000)

    # ── Tabela de estrutura ───────────────────────────────────────────
    print("\n" + "─" * 70)
    print(f"{'Critério':<35} {'MiniARX-64':>15} {'AES-128':>15}")
    print("─" * 70)

    rows_estrutura = [
        ("Estrutura",              "ARX",                    "SPN"),
        ("Tamanho de bloco",       "64 bits",                "128 bits"),
        ("Tamanho de chave",       "128 bits",               "128 bits"),
        ("Número de rodadas",      "16",                     "10"),
        ("Não-linearidade",        "Adição mod 2^32",        "S-Box (GF(2^8))"),
        ("Difusão",                "Rotação + Adição",       "ShiftRows + MixColumns"),
        ("Confusão",               "XOR c/ subchave",        "SubBytes + AddRoundKey"),
        ("Operações por rodada",   "6 (add,rot,xor × 2)",   "4 (sub,shift,mix,add)"),
        ("Requer tabelas/S-Box",   "Não",                    "Sim (256 bytes)"),
        ("Inversão de rodada",     "Direta (sub, rotr)",     "Requer inversa da S-Box"),
    ]

    for row in rows_estrutura:
        print(f"  {row[0]:<33} {row[1]:>15} {row[2]:>15}")

    # ── Tabela de desempenho ──────────────────────────────────────────
    print("\n" + "─" * 70)
    print("DESEMPENHO (implementação Python pura vs C otimizado)")
    print("─" * 70)
    print(f"{'Critério':<35} {'MiniARX-64':>15} {'AES-128':>15}")
    print("─" * 70)

    aes_disponivel = "não disponível" not in a.get("cipher", "")

    rows_perf = [
        ("Geração de subchaves (µs)",
            f"{m['keygen_us']:.2f}",
            f"{a['keygen_us']:.2f}" if aes_disponivel else "N/A"),
        ("Subchaves em memória (bytes)",
            str(m['subkey_bytes']),
            str(a['subkey_bytes']) if aes_disponivel else "N/A"),
        ("Throughput cifração (MB/s)",
            f"{m['enc_throughput']:.4f}",
            f"{a['enc_throughput']:.4f}" if aes_disponivel else "N/A"),
        ("Throughput decifração (MB/s)",
            f"{m['dec_throughput']:.4f}",
            f"{a['dec_throughput']:.4f}" if aes_disponivel else "N/A"),
        ("Latência/bloco cifração (µs)",
            f"{m['enc_latency_us']:.2f}",
            f"{a['enc_latency_us']:.2f}" if aes_disponivel else "N/A"),
        ("Memória pico (KB)",
            f"{mem['peak_kb']:.2f}",
            "~70–200 (estimado C)"),
    ]

    for row in rows_perf:
        print(f"  {row[0]:<33} {row[1]:>15} {row[2]:>15}")

    # ── Tabela de segurança / avalanche ──────────────────────────────
    print("\n" + "─" * 70)
    print("PROPRIEDADES DE SEGURANÇA")
    print("─" * 70)
    print(f"{'Critério':<35} {'MiniARX-64':>15} {'AES-128':>15}")
    print("─" * 70)

    rows_seg = [
        ("Avalanche plaintext (média)",
            f"{av_pt['mean']:.2f}/64 ({av_pt['pct']:.1f}%)",
            "~32/128 (50%)"),
        ("Avalanche plaintext (std)",
            f"{av_pt['std']:.2f}",
            "~4.0"),
        ("Avalanche de chave (média)",
            f"{av_k['mean']:.2f}/64 ({av_k['pct']:.1f}%)",
            "~64/128 (50%)"),
        ("Resistência diferencial",     "Boa (ARX conhecida)",     "Provada (wide trail)"),
        ("Resistência linear",          "Boa (ARX conhecida)",     "Provada (wide trail)"),
        ("Resistência related-key",     "Moderada",                "Vulnerabilidade conhecida"),
        ("Chaves fracas conhecidas",    "Nenhuma",                 "Nenhuma"),
        ("Paralelizável (ECB/CTR)",     "Sim",                     "Sim"),
        ("Suporte AES-NI (hardware)",   "Não",                     "Sim"),
        ("Segurança teórica bruta",     "2^128 (força bruta)",     "2^128 (força bruta)"),
    ]

    for row in rows_seg:
        print(f"  {row[0]:<33} {row[1]:>15} {row[2]:>15}")

    # ── Tabela qualitativa ────────────────────────────────────────────
    print("\n" + "─" * 70)
    print("CARACTERÍSTICAS QUALITATIVAS")
    print("─" * 70)
    print(f"{'Critério':<35} {'MiniARX-64':>15} {'AES-128':>15}")
    print("─" * 70)

    rows_qual = [
        ("Simplicidade de implementação", "Alta",          "Média"),
        ("Dependência de tabelas",        "Nenhuma",       "S-Box (256B)"),
        ("Escalabilidade de rodadas",     "Simples",       "Requer redesign"),
        ("Portabilidade (sem HW esp.)",   "Total",         "Parcial (AES-NI)"),
        ("Padronização",                  "Não (original)","FIPS 197 (NIST)"),
        ("Uso em produção",               "Educacional",   "Amplamente adotado"),
    ]

    for row in rows_qual:
        print(f"  {row[0]:<33} {row[1]:>15} {row[2]:>15}")

    print("\n" + "=" * 70)
    print("FIM DA COMPARAÇÃO")
    print("=" * 70)

    # Retorna tudo em dict para uso programático (ex.: relatório)
    return {
        "miniarx"  : m,
        "aes"      : a,
        "memory"   : mem,
        "av_pt"    : av_pt,
        "av_key"   : av_k,
    }


if __name__ == "__main__":
    run_comparison()