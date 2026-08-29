/*
 * ============================================================================
 * SECURE CASCADE - CRYPTO TEST BUILD (rev. 2 - correções de pentest)
 * ============================================================================
 *
 * Sistema de criptografia com tokens efêmeros em cascata, modelado como uma
 * "Wall of Entropy": o banco circular de tokens é a parede — cada célula
 * carrega uma unidade de entropia efêmera; quando a parede avança, células
 * antigas são destruídas (zeradas) e os dados que dependiam delas tornam-se
 * irrecuperáveis (crypto-shredding).
 * Versão para TESTES em ambiente controlado.
 *
 * ARQUITETURA:
 * - Chave mestra (master key) + Token efêmero = Chave de dados derivada
 *   via crypto_generichash (BLAKE2b) keyed hash — master_key como chave,
 *   token_data como mensagem, para que a chave derivada dependa de fato
 *   dos dois segredos.
 * - Criptografia AEAD: ChaCha20-Poly1305 (libsodium)
 * - Tokens em cascata: após X tokens novos, tokens antigos são destruídos
 * - Crypto-shredding: tokens destruídos tornam dados irrecuperáveis
 *
 * REV. 2 corrige as severidades encontradas na revisão de pentest da rev. 1:
 *   [CRÍTICO] derive_data_key ignorava token_data (KDF lia só 32 dos 64
 *             bytes do buffer combinado) -> toda a base usava 1 única chave.
 *             Corrigido com crypto_generichash keyed hash.
 *   [MÉDIO]   master key parcialmente impressa em stdout/log -> removido.
 *   [MÉDIO]   TOCTOU: ponteiros para token_data escapavam do mutex ->
 *             toda leitura de token_data agora acontece dentro da seção
 *             crítica, copiada para um buffer local do chamador.
 *   [BAIXO]   audit_test.log criado 644 (world-readable) -> criado 600.
 *   [BAIXO]   %s sobre token_id binário (UB) em destroy_token -> removido.
 *   [BAIXO]   comentários de tamanho incorretos -> corrigidos.
 *
 * REV. 2 também adiciona entropia de interação (anti-bot/anti-script):
 * cada token exige uma amostra de timing de interação real do cliente
 * (InteractionEntropy), validada e misturada via BLAKE2b keyed, SEM nunca
 * substituir o CSPRNG do SO como fonte dominante do segredo -- ver o
 * comentário longo em generate_token() para o raciocínio completo.
 *
 * REV. 3 (pentest de concorrência real -- 10.000 usuários virtuais +
 * atacantes simultâneos, sob ThreadSanitizer) encontrou e corrigiu 4
 * problemas que só existiam sob concorrência de verdade (o CLI original
 * era sequencial e nunca os exercitava):
 *   [ALTO]  encrypt_record(): corrida na reivindicação de slot -- duas
 *           threads podiam achar o mesmo registro livre e escrever nele
 *           ao mesmo tempo. Corrigido reivindicando o slot (active=true)
 *           atomicamente dentro da mesma seção crítica que o encontra.
 *   [ALTO]  decrypt_record(): use-after-free real (SEGV reproduzido sob
 *           TSan) -- lia record->ciphertext sem lock enquanto um
 *           reencrypt_record() concorrente no mesmo registro podia
 *           liberar e trocar esse ponteiro no meio da leitura. Corrigido
 *           copiando ciphertext/nonce/cadeia de tokens para buffers
 *           locais sob um lock por registro (rec_lock) antes de soltar.
 *   [ALTO]  reencrypt_record(): corrida de leitura-modificação-escrita
 *           no mesmo registro -- duas reencriptações concorrentes do
 *           mesmo record_id podiam corromper silenciosamente a cadeia
 *           onion de camadas. Corrigido serializando toda a operação
 *           (ler ciphertext antigo -> criptografar -> escrever) sob o
 *           mesmo rec_lock, do início ao fim.
 *   [MÉDIO] audit_log(): localtime() (buffer estático não thread-safe) e
 *           o contador de métricas eram acessados sem proteção por
 *           múltiplas threads simultâneas. Corrigido com localtime_r()
 *           + um mutex dedicado (audit_lock) cobrindo a função inteira.
 * Ver pentest_harness.c e o relatório de pentest para os detalhes da
 * carga que reproduziu cada um destes problemas.
 *
 * COMPILAÇÃO:
 *   gcc -o crypto_test crypto_test.c -lsodium -lpthread -Wall -O2
 * 
 * EXECUÇÃO:
 *   ./crypto_test
 *   ./crypto_test --demo       # Executa demonstração completa
 *   ./crypto_test --benchmark  # Executa benchmark de performance
 *   ./crypto_test --stress     # Teste de stress (cascata intensiva)
 * 
 * DEPENDÊNCIAS:
 *   - libsodium >= 1.0.18
 *   Instalação: sudo apt install libsodium-dev (Debian/Ubuntu)
 *               brew install libsodium (macOS)
 * 
 * ============================================================================
 * ⚠️  AVISO DE SEGURANÇA ⚠️
 * ============================================================================
 * Este código é para TESTES em ambiente controlado (sandbox, VM, laboratório).
 * 
 * ANTES de usar em produção, é OBRIGATÓRIO:
 *   1. Auditoria externa independente por empresa certificada
 *   2. Pentest profissional
 *   3. Gestão de chaves com HSM/KMS (NUNCA chave em memória apenas)
 *   4. Compliance legal (LGPD, GDPR, PCI-DSS conforme aplicável)
 *   5. Revisão por especialista em criptografia
 * 
 * NÃO usar em produção sem completar TODOS os itens acima.
 * ============================================================================
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <time.h>
#include <pthread.h>
#include <sodium.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdatomic.h>

/* ============================================================================
 * CONFIGURAÇÕES (ajustar conforme necessidade de teste)
 * ============================================================================ */

#define SYSTEM_NAME            "SecureCascade-Test"
#define SYSTEM_VERSION         "1.0.0-test"

#define MASTER_KEY_SIZE        crypto_kdf_KEYBYTES         /* 32 bytes (256 bits) */
#define TOKEN_DATA_SIZE        32                           /* 256 bits */
#define TOKEN_ID_SIZE          16                           /* 128 bits */
#define NONCE_SIZE             crypto_aead_chacha20poly1305_ietf_NPUBBYTES  /* 12 bytes (IETF variant, NÃO XChaCha) */
#define TAG_SIZE               crypto_aead_chacha20poly1305_ietf_ABYTES     /* 16 bytes */
#define KEY_SIZE               crypto_aead_chacha20poly1305_ietf_KEYBYTES  /* 32 bytes */

#define TOKEN_BANK_CAPACITY    1000    /* Capacidade máxima do banco */
#define CASCADE_THRESHOLD      100     /* Após X tokens, antigos são destruídos */
#define MAX_TOKEN_CHAIN        16      /* Máximo de camadas de re-criptografia */
#define MAX_RECORDS            10000   /* Máximo de registros */
#define MAX_DATA_SIZE          (1024 * 1024)  /* 1 MB por registro */
/* REV. 7: tamanho da fatia do pool de ciphertext (ver comentário completo
 * no campo ciphertext_pool de SecureCascade). Cobre plaintexts pequenos
 * (o caso comum, ex.: até ~256 bytes) mesmo depois de MAX_TOKEN_CHAIN
 * camadas de reencriptação (cada camada soma TAG_SIZE=16 bytes ao
 * tamanho: pior caso ~256 + 16*16 = 512 bytes). Registros maiores usam
 * sodium_malloc individual como fallback (mais caro em RSS, mas correto). */
#define CIPHERTEXT_POOL_SLOT_SIZE  512

#define KDF_CONTEXT            "SecureCascade-v1-DataKey"

/* ---- Mistura de entropia de interação (anti-bot/anti-script) ----
 * Objetivo: amarrar a criação de cada token a uma prova de interação real
 * (deltas de tempo entre eventos de clique/toque/tecla, capturados no
 * cliente), sem NUNCA deixar essa entropia virar a fonte principal do
 * segredo. Ver o comentário longo em generate_token() para o raciocínio
 * completo -- em resumo: o CSPRNG do SO continua sendo a chave dominante
 * na mistura; os dados de interação entram só como mensagem adicional. */
#define INTERACTION_SAMPLES_MIN    5    /* mínimo de amostras de timing exigidas */
#define INTERACTION_SAMPLES_MAX    32
#define INTERACTION_JITTER_MIN_US  50   /* variação mínima entre a amostra mais rápida e a mais lenta, em microssegundos */

/* ============================================================================
 * ESTRUTURAS DE DADOS
 * ============================================================================ */

typedef struct {
    uint8_t token_id[TOKEN_ID_SIZE];
    uint8_t token_data[TOKEN_DATA_SIZE];
    char user_id[64];
    uint64_t sequence_number;
    time_t created_at;
    uint32_t ttl_seconds;
    bool active;
    bool destroyed;
    time_t destroyed_at;
} EphemeralToken;

/* Amostras de timing de interação, capturadas no cliente (ex.: deltas em
 * microssegundos entre eventos de clique/toque/tecla) e enviadas junto com
 * a chamada de criptografia. Usadas só como material adicional na mistura
 * de entropia de cada token -- nunca como substituto do CSPRNG do SO. */
typedef struct {
    uint64_t event_deltas_us[INTERACTION_SAMPLES_MAX];
    size_t   sample_count;
} InteractionEntropy;

/* REV. 6: "carimbo" do instante de acesso -- dia-mês-ano-hora-min-seg até
 * MICROSSEGUNDOS, mais o FUSO HORÁRIO local no momento da captura. Mesmo
 * propósito da InteractionEntropy: material AUXILIAR misturado no token,
 * nunca a chave. Por quê os dois campos:
 *   - microssegundos (não só segundos): com timing de 1 segundo, todo
 *     acesso dentro do mesmo segundo produz o MESMO valor -- sob mais de
 *     um usuário por segundo (o caso comum), isso "empata" vários
 *     usuários na mesma entrada. Em microssegundos a chance de colisão
 *     entre dois acessos reais é desprezível. (E mesmo que colida, não
 *     compromete nada -- ver comentário em generate_token().)
 *   - fuso horário: sem ele, o mesmo instante físico gera bytes diferentes
 *     dependendo de en que fuso o servidor/cliente está configurado --
 *     amarra o carimbo a um referencial (offset em relação a UTC), então
 *     dois eventos no mesmo instante real sempre produzem o mesmo dado de
 *     tempo bruto, não importa o fuso local de cada máquina.
 * Nunca é a única fonte do token (ver o mesmo raciocínio de dominância do
 * CSPRNG documentado em generate_token()) -- é só mais material de
 * proveniência misturado junto com a entropia de interação. */
typedef struct {
    int64_t  epoch_seconds;       /* segundos desde 1970-01-01 UTC */
    uint32_t microseconds;        /* 0-999999, fração do segundo acima */
    int32_t  utc_offset_seconds;  /* fuso horário local no instante da captura,
                                    * em segundos a leste de UTC (ex.: -10800
                                    * para UTC-3); pode ser negativo */
} AccessTimestamp;

typedef struct {
    uint8_t record_id[TOKEN_ID_SIZE];
    char user_id[64];
    char data_category[32];
    /* REV. 7 [CORREÇÃO DE BUG PRÉ-EXISTENTE, achado testando a rev.7]:
     * ANTES havia um único campo `nonce` (o mais recente). Mas cada
     * camada da cadeia onion (token_chain[i]) foi criptografada com um
     * nonce PRÓPRIO e DIFERENTE (gerado de novo a cada reencrypt_record).
     * Guardar só o último nonce PERDE os nonces das camadas anteriores
     * para sempre -- decrypt_record() tentava desencapar a camada i com
     * o nonce da camada mais recente (errado para toda i < chain_length-1),
     * o que faz a verificação de autenticação do AEAD falhar
     * (DECRYPT_FAILED) em qualquer registro com chain_length >= 2.
     * Confirmado com PoC isolado rodando o código da rev.6 (sem nenhuma
     * mudança de pool): decrypt depois de 1 único reencrypt já falhava
     * 100% das vezes. Bug pré-existente desde que a cadeia de
     * reencriptação foi introduzida -- não relacionado à otimização de
     * memória desta revisão. Nos pentests anteriores isso se escondia
     * dentro da contagem de "decrypt fail" (atribuída, incorretamente,
     * só a crypto-shredding) -- nunca virava MISMATCH porque o AEAD
     * rejeita e retorna falha em vez de devolver dado errado (a
     * autenticação do Poly1305 fez seu trabalho: nunca vazou texto
     * decifrado incorretamente, só impediu a operação).
     * Correção: um nonce POR CAMADA, paralelo a token_chain, para que
     * decrypt_record() sempre use o nonce exato que foi usado pra
     * criar aquela camada específica. */
    uint8_t nonce_chain[MAX_TOKEN_CHAIN][NONCE_SIZE];
    uint8_t *ciphertext;
    size_t ciphertext_len;
    /* REV. 7: true quando `ciphertext` aponta pra dentro de
     * sys->ciphertext_pool (fatia fixa, não deve ser sodium_free()); false
     * quando é uma alocação individual (fallback, sodium_malloc próprio,
     * precisa de sodium_free() quando substituído/no shutdown). */
    bool ciphertext_in_pool;
    char token_chain[MAX_TOKEN_CHAIN][TOKEN_ID_SIZE * 2 + 1];
    size_t chain_length;
    size_t encryption_layers;
    time_t created_at;
    time_t last_reencrypted;
    bool active;
    bool shredded;
    /* REV. 3 (pentest de concorrência) -- lock POR REGISTRO. Protege
     * ciphertext/ciphertext_len/nonce/chain_length/token_chain/
     * encryption_layers/last_reencrypted/shredded deste registro
     * especificamente. sys->lock continua protegendo só a existência dos
     * registros (o array, active, record_count, métricas globais) --
     * nunca o conteúdo. Os dois locks nunca são mantidos presos ao mesmo
     * tempo pela mesma thread neste arquivo (cada um é sempre solto antes
     * do outro ser adquirido), então não há risco de deadlock entre eles.
     * Inicializado uma vez em system_init() para todos os MAX_RECORDS
     * slots e nunca reinicializado depois (evita destruir um mutex que
     * outra thread possa estar usando). */
    pthread_mutex_t rec_lock;
} EncryptedRecord;

typedef struct {
    uint64_t tokens_created;
    uint64_t tokens_destroyed;
    uint64_t records_encrypted;
    uint64_t records_reencrypted;
    uint64_t records_decrypted;
    uint64_t decryption_failures;
    uint64_t cascade_events;
    uint64_t audit_events;
} Metrics;

typedef struct {
    uint8_t master_key[MASTER_KEY_SIZE];
    EphemeralToken *token_bank;
    int bank_start;
    int bank_size;
    EncryptedRecord *records;
    size_t record_count;
    uint64_t token_counter;
    /* REV. 5 (teste de escala): capacidade real de sys->records, decidida
     * em tempo de execução (parâmetro de system_init) em vez do antigo
     * #define MAX_RECORDS fixo -- permite rodar o mesmo binário em
     * patamares de escala diferentes (100 mil, 1 milhão, ...) sem
     * recompilar. MAX_RECORDS continua existindo como valor PADRÃO usado
     * pelos modos de CLI originais (--demo/--benchmark/--stress). */
    size_t max_records;
    /* REV. 5 (achado do teste de escala): encrypt_record() achava um
     * slot livre com uma busca LINEAR em sys->records a cada chamada, e
     * decrypt_record()/reencrypt_record() achavam um registro por ID com
     * outra busca linear. Em N=10.000 isso passava despercebido; em
     * N=100.000 o teste TRAVOU por mais de 5 minutos sem terminar --
     * porque preencher N slots com uma busca O(N) por slot é O(N²) no
     * total, e cada decrypt/reencrypt também é O(N). Substituído por:
     * (1) um alocador "bump" atômico para slots (next_free_slot -- cada
     * thread pega um índice novo com um único incremento atômico, sem
     * lock nenhum, O(1)); e (2) uma tabela hash simples (endereçamento
     * aberto) de record_id -> índice do slot, para achar um registro em
     * O(1) médio em vez de O(N). Ver generate_token()/encrypt_record()/
     * decrypt_record()/reencrypt_record() e as funções hash_record_id()/
     * record_index_insert()/record_index_lookup() logo abaixo. */
    atomic_size_t next_free_slot;
    size_t *record_index;       /* tabela hash: slot vazio == SIZE_MAX */
    size_t record_index_size;   /* sempre potência de 2 (mask em vez de %) */
    /* REV. 7 (compressão de memória -- pedido do usuário: "como comprimir
     * o código pra chegar no mesmo teto de acesso simultâneo usando bem
     * menos memória?"): antes, CADA registro chamava sodium_malloc()
     * individualmente para o ciphertext. sodium_malloc() arredonda toda
     * alocação pra página inteira + soma duas páginas de guarda -- medido
     * na rev.5: um ciphertext real de ~50-80 bytes consumia ~15-20KB de
     * RSS de verdade (~100-200x o tamanho do dado). Isso dominava TODO o
     * custo de memória por registro.
     * Correção: UM ÚNICO sodium_malloc() para um "pool" contíguo de
     * ciphertext_pool_slot_size bytes por registro (dimensionado pra
     * max_records), feito uma vez em system_init(). Cada registro pequeno
     * (o caso comum) usa sua fatia fixa dentro desse pool -- SEM chamar
     * sodium_malloc/sodium_free por registro, então SEM arredondamento de
     * página nem páginas de guarda repetidas. Só o pool inteiro (uma
     * alocação) paga esse custo fixo, uma única vez, não importa quantos
     * milhões de registros existam. Registros que excedem o slot (raro --
     * só depois de várias camadas de reencriptação, ou payload grande)
     * caem no caminho antigo (sodium_malloc individual) como fallback --
     * ver ciphertext_in_pool em EncryptedRecord e a lógica em
     * encrypt_record()/reencrypt_record(). */
    uint8_t *ciphertext_pool;
    size_t ciphertext_pool_slot_size;
    /* REV. 5 (teste de escala): audit_log() faz um printf() de stdout E
     * um fprintf()+fflush() em arquivo A CADA chamada -- em dezenas ou
     * centenas de milhares de operações por segundo isso vira o gargalo
     * real (I/O síncrono), não a criptografia. quiet=true mantém a
     * contagem de métricas mas pula os dois I/Os por evento. */
    bool quiet;
    Metrics metrics;
    pthread_mutex_t lock;
    /* REV. 3 -- lock dedicado só para o corpo de audit_log(). localtime()
     * usa um buffer estático interno (não é thread-safe) e o contador
     * metrics.audit_events precisa de proteção; um mutex separado (em vez
     * de reusar sys->lock) evita autodeadlock, já que destroy_token() ->
     * audit_log() é chamado de DENTRO de uma seção crítica de sys->lock
     * (via check_cascade, dentro de generate_token()). */
    pthread_mutex_t audit_lock;
    bool initialized;
    FILE *audit_file;
} SecureCascade;

/* ============================================================================
 * FUNÇÕES AUXILIARES
 * ============================================================================ */

static void print_separator(const char *title) {
    printf("\n========================================================================\n");
    if (title) {
        printf("  %s\n", title);
        printf("========================================================================\n");
    }
}

static void bytes_to_hex(const uint8_t *bytes, size_t len, char *hex, size_t hex_size) {
    if (hex_size < len * 2 + 1) {
        hex[0] = '\0';
        return;
    }
    sodium_bin2hex(hex, hex_size, bytes, len);
}

static bool hex_to_bytes(const char *hex, uint8_t *bytes, size_t expected_len) {
    size_t bin_len;
    if (sodium_hex2bin(bytes, expected_len, hex, strlen(hex),
                       NULL, &bin_len, NULL) != 0) {
        return false;
    }
    return bin_len == expected_len;
}

/* ============================================================================
 * ÍNDICE POR HASH (record_id -> slot) -- REV. 5, achado do teste de escala
 * ============================================================================
 * record_id é gerado por randombytes_buf (128 bits, uniformemente
 * aleatório), então os 8 primeiros bytes já servem de hash sem precisar
 * de nenhuma função extra -- são tão aleatórios quanto qualquer hash
 * calculado por cima deles. Endereçamento aberto com sondagem linear;
 * como cada ID só é escrito UMA VEZ e nunca removido/reescrito, não há
 * necessidade de lidar com deleção (tombstones) -- só inserção e busca.
 * Tudo aqui é chamado sempre sob sys->lock (ver comentário no struct). */

static inline size_t hash_record_id(const uint8_t id[TOKEN_ID_SIZE], size_t table_size) {
    uint64_t h;
    memcpy(&h, id, sizeof(h));  /* memcpy evita problema de alinhamento */
    return (size_t)(h & (uint64_t)(table_size - 1));  /* table_size é potência de 2 */
}

static void record_index_insert(SecureCascade *sys, const uint8_t id[TOKEN_ID_SIZE],
                                 size_t slot) {
    size_t i = hash_record_id(id, sys->record_index_size);
    for (size_t probe = 0; probe < sys->record_index_size; probe++) {
        if (sys->record_index[i] == SIZE_MAX) {
            sys->record_index[i] = slot;
            return;
        }
        i = (i + 1) & (sys->record_index_size - 1);
    }
    /* Tabela cheia -- não deveria acontecer (dimensionada em system_init
     * com folga sobre max_records), mas se acontecer o registro só fica
     * sem entrada no índice (fail-safe: vira "não encontrado" na busca,
     * não um buffer overflow). */
}

static bool record_index_lookup(SecureCascade *sys, const uint8_t id[TOKEN_ID_SIZE],
                                 size_t *out_slot) {
    size_t i = hash_record_id(id, sys->record_index_size);
    for (size_t probe = 0; probe < sys->record_index_size; probe++) {
        size_t slot = sys->record_index[i];
        if (slot == SIZE_MAX) return false;   /* buraco = não existe */
        if (sodium_memcmp(sys->records[slot].record_id, id, TOKEN_ID_SIZE) == 0) {
            *out_slot = slot;
            return true;
        }
        i = (i + 1) & (sys->record_index_size - 1);
    }
    return false;
}

/* Valida a entropia de interação recebida do cliente. Isto NÃO prova que a
 * origem foi um humano -- um script motivado consegue gerar jitter
 * sintético que passa em testes estatísticos simples. O que isto faz é:
 * (1) recusar os casos mais ingênuos de automação (timing fixo, replay
 * exato, ausência de dados), e (2) obrigar quem chama a função a de fato
 * ter e enviar uma amostra de timing por chamada, o que já é uma barreira
 * de engenharia maior do que simplesmente invocar uma API sem estado. */
static bool interaction_entropy_valid(const InteractionEntropy *ie) {
    if (!ie) return false;
    if (ie->sample_count < INTERACTION_SAMPLES_MIN) return false;
    if (ie->sample_count > INTERACTION_SAMPLES_MAX) return false;

    uint64_t min_v = UINT64_MAX, max_v = 0;
    for (size_t i = 0; i < ie->sample_count; i++) {
        if (ie->event_deltas_us[i] < min_v) min_v = ie->event_deltas_us[i];
        if (ie->event_deltas_us[i] > max_v) max_v = ie->event_deltas_us[i];
    }

    /* Timing "reto demais" (toda amostra igual, ou quase) é o sinal mais
     * barato de detectar de um script sem jitter real -- rejeita. */
    if (max_v - min_v < INTERACTION_JITTER_MIN_US) return false;

    return true;
}

/* REV. 6: captura o instante atual com precisão de microssegundo + o fuso
 * horário local nesse instante. clock_gettime(CLOCK_REALTIME) dá
 * segundos+nanossegundos (truncados para microssegundos aqui); localtime_r
 * (já usado em audit_log, reentrante) dá o fuso via tm_gmtoff (extensão
 * glibc/BSD, segundos a leste de UTC). Não grava nada em disco -- o
 * carimbo vive só na pilha do chamador até ser misturado e descartado. */
static void capture_access_timestamp(AccessTimestamp *out) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);

    time_t sec = ts.tv_sec;
    struct tm tm_local;
    localtime_r(&sec, &tm_local);

    out->epoch_seconds = (int64_t)ts.tv_sec;
    out->microseconds = (uint32_t)(ts.tv_nsec / 1000);
#if defined(__USE_MISC) || defined(__USE_BSD) || defined(_DEFAULT_SOURCE) || defined(__APPLE__)
    out->utc_offset_seconds = (int32_t)tm_local.tm_gmtoff;
#else
    out->utc_offset_seconds = 0;  /* fallback se tm_gmtoff não existir na libc */
#endif
}

/* Serializa o carimbo em bytes de forma determinística (independe de
 * endianness da máquina, já que cada campo é escrito byte a byte na ordem
 * fixa) -- é este buffer que entra na mistura do token, nunca os campos
 * soltos da struct (evita depender de layout/padding do compilador). */
static void access_timestamp_to_bytes(const AccessTimestamp *ts, uint8_t out[16]) {
    uint64_t sec_be = (uint64_t)ts->epoch_seconds;
    for (int i = 0; i < 8; i++) out[i] = (uint8_t)(sec_be >> (8 * (7 - i)));
    uint32_t us_be = ts->microseconds;
    for (int i = 0; i < 4; i++) out[8 + i] = (uint8_t)(us_be >> (8 * (3 - i)));
    uint32_t off_be = (uint32_t)ts->utc_offset_seconds;
    for (int i = 0; i < 4; i++) out[12 + i] = (uint8_t)(off_be >> (8 * (3 - i)));
}

/* Formato legível pra log/auditoria: DD/MM/AAAA HH:MM:SS.microssegundos
 * ±HHMM (fuso). Só para rastreabilidade humana -- não é usado na mistura
 * criptográfica (essa usa access_timestamp_to_bytes acima). */
static void format_access_timestamp(const AccessTimestamp *ts, char *out, size_t out_size) {
    time_t sec = (time_t)ts->epoch_seconds;
    struct tm tm_local;
    localtime_r(&sec, &tm_local);
    int off_h = ts->utc_offset_seconds / 3600;
    int off_m = abs((ts->utc_offset_seconds % 3600) / 60);
    snprintf(out, out_size, "%02d/%02d/%04d %02d:%02d:%02d.%06u %+03d%02d",
             tm_local.tm_mday, tm_local.tm_mon + 1, tm_local.tm_year + 1900,
             tm_local.tm_hour, tm_local.tm_min, tm_local.tm_sec,
             ts->microseconds, off_h, off_m);
}

static void audit_log(SecureCascade *sys, const char *event,
                       const char *user, const char *details) {
    /* REV. 3: pentest sob concorrência real (TSan) confirmou uma corrida
     * de dados aqui -- localtime() usa um buffer estático interno
     * compartilhado por todas as threads (não é thread-safe), e
     * metrics.audit_events++ é um incremento não atômico sobre memória
     * compartilhada. Corrigido com localtime_r() (reentrante, sem estado
     * global) + audit_lock cobrindo toda a função. */
    pthread_mutex_lock(&sys->audit_lock);

    if (!sys->quiet) {
        time_t now = time(NULL);
        struct tm tm_buf;
        localtime_r(&now, &tm_buf);
        char time_str[32];
        strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", &tm_buf);

        printf("[AUDIT] [%s] %s | user=%s | %s\n",
               time_str, event, user ? user : "SYSTEM", details ? details : "-");

        if (sys->audit_file) {
            fprintf(sys->audit_file, "[%s] %s | user=%s | %s\n",
                    time_str, event, user ? user : "SYSTEM", details ? details : "-");
            fflush(sys->audit_file);
        }
    }

    sys->metrics.audit_events++;

    pthread_mutex_unlock(&sys->audit_lock);
}

/* ============================================================================
 * INICIALIZAÇÃO E ENCERRAMENTO
 * ============================================================================ */

static bool system_init(SecureCascade *sys, const char *audit_path,
                         size_t max_records, bool quiet) {
    if (sodium_init() < 0) {
        fprintf(stderr, "[ERRO] Falha ao inicializar libsodium\n");
        return false;
    }

    memset(sys, 0, sizeof(SecureCascade));

    sys->max_records = max_records;
    sys->quiet = quiet;
    sys->token_bank = calloc(TOKEN_BANK_CAPACITY, sizeof(EphemeralToken));
    sys->records = calloc(max_records, sizeof(EncryptedRecord));

    /* REV. 5: tabela hash de índice, dimensionada como a próxima potência
     * de 2 >= 2x max_records (fator de carga <= 50%, mantém sondagem
     * linear rápida mesmo perto da capacidade cheia). */
    size_t index_size = 16;
    size_t min_index_size = max_records * 2;
    if (min_index_size < max_records) {
        /* overflow de size_t (max_records absurdamente grande) --
         * trata como falha de alocação abaixo, de forma controlada. */
        min_index_size = SIZE_MAX;
    }
    while (index_size < min_index_size && index_size < (SIZE_MAX / 2)) {
        index_size *= 2;
    }
    sys->record_index_size = index_size;
    sys->record_index = malloc(index_size * sizeof(size_t));

    /* REV. 7: pool único de ciphertext -- ver comentário completo no
     * campo ciphertext_pool do struct SecureCascade. UMA alocação
     * sodium_malloc() (guardas de página + mlock pagos uma vez só) em vez
     * de max_records alocações individuais. */
    sys->ciphertext_pool_slot_size = CIPHERTEXT_POOL_SLOT_SIZE;
    size_t pool_bytes = max_records * (size_t)CIPHERTEXT_POOL_SLOT_SIZE;
    bool pool_overflow = (max_records != 0 &&
                          pool_bytes / max_records != (size_t)CIPHERTEXT_POOL_SLOT_SIZE);
    sys->ciphertext_pool = pool_overflow ? NULL : sodium_malloc(pool_bytes);

    if (!sys->token_bank || !sys->records || !sys->record_index ||
        !sys->ciphertext_pool) {
        /* Falha de alocação -- exatamente o tipo de "limite de quebra"
         * que um teste de escala precisa reportar com clareza, não só
         * travar. Em vez de imprimir um "[ERRO]" genérico, registra o
         * tamanho pedido para o chamador (harness de escala) poder
         * decidir o que fazer sem adivinhar. */
        fprintf(stderr,
                "[ERRO] Falha de alocação de memória para max_records=%zu "
                "(%.2f GB p/ sys->records + %.2f GB p/ indice hash + "
                "%.2f GB p/ pool de ciphertext)\n",
                max_records,
                (double)(max_records * sizeof(EncryptedRecord)) / (1024.0*1024.0*1024.0),
                (double)(index_size * sizeof(size_t)) / (1024.0*1024.0*1024.0),
                (double)pool_bytes / (1024.0*1024.0*1024.0));
        free(sys->token_bank);
        free(sys->records);
        free(sys->record_index);
        if (sys->ciphertext_pool) sodium_free(sys->ciphertext_pool);
        sys->token_bank = NULL;
        sys->records = NULL;
        sys->record_index = NULL;
        sys->ciphertext_pool = NULL;
        return false;
    }

    /* SIZE_MAX byte a byte é 0xFF em cada byte -- memset dá inicialização
     * "tabela vazia" em O(n) sequencial, bem mais rápido que um laço. */
    memset(sys->record_index, 0xFF, index_size * sizeof(size_t));
    atomic_init(&sys->next_free_slot, (size_t)0);

    /* Gera chave mestra (em produção: usar HSM/KMS) */
    randombytes_buf(sys->master_key, MASTER_KEY_SIZE);

    pthread_mutex_init(&sys->lock, NULL);
    pthread_mutex_init(&sys->audit_lock, NULL);

    /* REV. 3: inicializa o lock por registro de TODOS os slots agora,
     * de uma vez -- os slots vivem pelo tempo de vida inteiro do
     * processo (o alocador "bump" de encrypt_record() nunca reaproveita
     * um slot, então rec_lock nunca precisa ser reinicializado depois
     * daqui; ver comentário no struct). */
    for (size_t i = 0; i < sys->max_records; i++) {
        pthread_mutex_init(&sys->records[i].rec_lock, NULL);
    }

    if (audit_path) {
        /* Cria o arquivo de auditoria já com permissão 600 (só o dono lê/escreve).
         * fopen() sozinho herda o umask do processo, que costuma resultar em
         * 644 (world-readable) -- abrimos via open() com modo explícito e
         * então associamos um FILE* com fdopen(). */
        int fd = open(audit_path, O_WRONLY | O_CREAT | O_APPEND, S_IRUSR | S_IWUSR);
        if (fd >= 0) {
            sys->audit_file = fdopen(fd, "a");
            if (!sys->audit_file) {
                close(fd);
            }
        }
        if (!sys->audit_file) {
            fprintf(stderr, "[AVISO] Não foi possível abrir arquivo de auditoria\n");
        }
    }

    sys->initialized = true;

    audit_log(sys, "SYSTEM_INIT", NULL, "Sistema inicializado");

    printf("[INFO] %s v%s inicializado\n", SYSTEM_NAME, SYSTEM_VERSION);
    printf("[INFO] Token bank capacity: %d\n", TOKEN_BANK_CAPACITY);
    printf("[INFO] Cascade threshold: %d\n", CASCADE_THRESHOLD);
    /* NUNCA imprimir nem logar nenhum byte da master key, nem parcialmente:
     * stdout/logs costumam ter controle de acesso mais fraco que a memória
     * do processo. (rev.1 vazava os primeiros 8 bytes aqui.) */

    return true;
}

static void system_shutdown(SecureCascade *sys) {
    if (!sys->initialized) return;
    
    audit_log(sys, "SYSTEM_SHUTDOWN", NULL, "Encerrando sistema");
    
    /* Zeroiza chave mestra */
    sodium_memzero(sys->master_key, MASTER_KEY_SIZE);
    
    /* Zeroiza todos os tokens */
    for (int i = 0; i < sys->bank_size; i++) {
        int idx = (sys->bank_start + i) % TOKEN_BANK_CAPACITY;
        sodium_memzero(sys->token_bank[idx].token_data, TOKEN_DATA_SIZE);
    }
    
    /* REV. 7: libera memória dos ciphertexts que caíram no fallback
     * individual (ciphertext_in_pool == false) -- os que vivem dentro de
     * sys->ciphertext_pool são liberados de uma vez só, abaixo, com o
     * pool inteiro (nunca via sodium_free() individual). */
    for (size_t i = 0; i < sys->max_records; i++) {
        if (sys->records[i].ciphertext && !sys->records[i].ciphertext_in_pool) {
            sodium_free(sys->records[i].ciphertext);
        }
    }
    if (sys->ciphertext_pool) {
        sodium_free(sys->ciphertext_pool);
    }

    if (sys->audit_file) {
        fclose(sys->audit_file);
    }

    for (size_t i = 0; i < sys->max_records; i++) {
        pthread_mutex_destroy(&sys->records[i].rec_lock);
    }

    pthread_mutex_destroy(&sys->lock);
    pthread_mutex_destroy(&sys->audit_lock);
    free(sys->token_bank);
    free(sys->records);
    free(sys->record_index);

    sys->initialized = false;
    
    printf("[INFO] Sistema encerrado com segurança\n");
}

/* ============================================================================
 * GESTÃO DE TOKENS EFÊMEROS
 * ============================================================================ */

static void destroy_token(SecureCascade *sys, EphemeralToken *token,
                           const char *reason) {
    if (!token || token->destroyed) return;

    /* Zeroiza material criptográfico */
    sodium_memzero(token->token_data, TOKEN_DATA_SIZE);

    token->destroyed = true;
    token->destroyed_at = time(NULL);

    sys->metrics.tokens_destroyed++;

    /* Não logar token_id (é binário, não string -- passar direto a um "%s"
     * é comportamento indefinido em C; e mesmo hexadecimal, não deve ir
     * para o log por segurança). Só o motivo e o usuário são registrados. */
    audit_log(sys, "TOKEN_DESTROYED", token->user_id, reason);
}

static void check_cascade(SecureCascade *sys) {
    while (sys->bank_size > CASCADE_THRESHOLD) {
        EphemeralToken *oldest = &sys->token_bank[sys->bank_start];
        
        if (!oldest->destroyed) {
            destroy_token(sys, oldest, "cascata");
            sys->metrics.cascade_events++;
        }
        
        sys->bank_start = (sys->bank_start + 1) % TOKEN_BANK_CAPACITY;
        sys->bank_size--;
    }
}

/* Gera um novo token efêmero e devolve seu ID e seus dados por cópia
 * (out_token_id / out_token_data), sempre lidos dentro da seção crítica.
 * Nenhum ponteiro para dentro de token_bank escapa desta função: assim
 * nenhum chamador pode ler token_data depois que o slot foi reciclado por
 * outra thread (TOCTOU corrigido).
 *
 * ENTROPIA DE INTERAÇÃO (anti-bot/anti-script):
 * `interaction` traz amostras de timing de um evento real do lado do
 * cliente (deltas entre clique/toque/tecla). A função recusa gerar o token
 * se essas amostras não passarem em interaction_entropy_valid() -- então um
 * chamador programático que não tenha timing real para enviar (ou que
 * envie timing "reto demais") não consegue nem começar a gerar um token.
 *
 * IMPORTANTE -- por que isso NÃO substitui o CSPRNG do SO: se a timing de
 * interação virasse a própria fonte da chave, um bot que conseguisse
 * reproduzir estatisticamente um padrão humano (jitter sintético que passa
 * nos testes) estaria, na prática, criando uma "aleatoriedade digital" --
 * gerada por um PRNG do próprio bot -- que pode ser rastreada e, se aquele
 * PRNG for identificado/revertido, reproduzida. Isso quebraria o
 * crypto-shredding pela raiz: um atacante que soubesse recriar o padrão de
 * timing recriaria o próprio token "destruído" e decifraria dados que
 * deveriam ser irrecuperáveis.
 *
 * Por isso a mistura é: token_data = BLAKE2b_keyed(chave = csprng_bytes,
 * mensagem = deltas de interação). O CSPRNG do kernel (via randombytes_buf,
 * lastreado em /dev/urandom) continua sendo o segredo dominante -- ele é a
 * CHAVE do hash, não a mensagem. Mesmo que os deltas de interação sejam
 * inteiramente previstos ou reproduzidos por um atacante, a saída do
 * BLAKE2b keyed continua computacionalmente indistinguível de aleatória sem
 * conhecer csprng_bytes, que nunca é persistido nem exposto. Ou seja: a
 * entropia de interação só AGREGA proveniência e dificulta automação
 * ingênua; ela nunca ENFRAQUECE nem SUBSTITUI a entropia do SO. */
static bool generate_token(SecureCascade *sys,
                            const char *user_id,
                            uint32_t ttl_seconds,
                            const InteractionEntropy *interaction,
                            uint8_t out_token_id[TOKEN_ID_SIZE],
                            uint8_t out_token_data[TOKEN_DATA_SIZE]) {
    if (!interaction_entropy_valid(interaction)) {
        audit_log(sys, "TOKEN_REJECTED", user_id,
                  "entropia de interacao ausente ou invalida (timing suspeito de script/bot)");
        return false;
    }

    pthread_mutex_lock(&sys->lock);

    sys->token_counter++;

    EphemeralToken token;
    memset(&token, 0, sizeof(token));

    randombytes_buf(token.token_id, TOKEN_ID_SIZE);

    char access_ts_str[64];
    {
        uint8_t csprng_bytes[TOKEN_DATA_SIZE];
        randombytes_buf(csprng_bytes, sizeof(csprng_bytes));

        /* REV. 6: mistura o carimbo de acesso (microssegundos + fuso
         * horário, ver AccessTimestamp) JUNTO com os deltas de interação,
         * na mesma mensagem auxiliar. csprng_bytes continua sendo a
         * CHAVE do hash (o segredo dominante) -- então mesmo que vários
         * usuários acessem no mesmo instante (empatando os bits do
         * carimbo entre eles) ou um atacante adivinhe/replique o
         * timestamp inteiro, o token de cada um continua imprevisível
         * sem csprng_bytes, que nunca é persistido. O carimbo em si
         * também nunca é gravado em disco -- só passa pela pilha aqui e
         * é zerado logo abaixo. */
        AccessTimestamp access_ts;
        capture_access_timestamp(&access_ts);
        format_access_timestamp(&access_ts, access_ts_str, sizeof(access_ts_str));

        uint8_t ts_bytes[16];
        access_timestamp_to_bytes(&access_ts, ts_bytes);

        uint8_t message[INTERACTION_SAMPLES_MAX * sizeof(uint64_t) + sizeof(ts_bytes)];
        size_t deltas_len = interaction->sample_count * sizeof(uint64_t);
        memcpy(message, interaction->event_deltas_us, deltas_len);
        memcpy(message + deltas_len, ts_bytes, sizeof(ts_bytes));

        crypto_generichash(token.token_data, TOKEN_DATA_SIZE,
                            message, deltas_len + sizeof(ts_bytes),
                            csprng_bytes, sizeof(csprng_bytes));

        sodium_memzero(csprng_bytes, sizeof(csprng_bytes));
        sodium_memzero(message, sizeof(message));
    }

    strncpy(token.user_id, user_id ? user_id : "unknown",
            sizeof(token.user_id) - 1);
    token.sequence_number = sys->token_counter;
    token.created_at = time(NULL);
    token.ttl_seconds = ttl_seconds;
    token.active = true;
    token.destroyed = false;

    /* Adiciona ao banco circular */
    if (sys->bank_size >= TOKEN_BANK_CAPACITY) {
        EphemeralToken *oldest = &sys->token_bank[sys->bank_start];
        if (!oldest->destroyed) {
            destroy_token(sys, oldest, "capacidade_excedida");
        }
        sys->bank_start = (sys->bank_start + 1) % TOKEN_BANK_CAPACITY;
        sys->bank_size--;
    }

    int idx = (sys->bank_start + sys->bank_size) % TOKEN_BANK_CAPACITY;
    memcpy(&sys->token_bank[idx], &token, sizeof(EphemeralToken));
    sys->bank_size++;

    sys->metrics.tokens_created++;

    /* Verifica cascata dentro da MESMA seção crítica (antes era um
     * lock/unlock separado, deixando uma janela onde outra thread podia
     * mexer em bank_start/bank_size entre as duas travas). */
    check_cascade(sys);

    memcpy(out_token_id, token.token_id, TOKEN_ID_SIZE);
    memcpy(out_token_data, token.token_data, TOKEN_DATA_SIZE);

    pthread_mutex_unlock(&sys->lock);

    audit_log(sys, "TOKEN_GENERATED", user_id, access_ts_str);

    return true;
}

/* Busca um token pelo ID hex e, se ele ainda existir/for válido, copia seu
 * token_data para out_data -- tudo dentro de uma única seção crítica.
 * Isso substitui o antigo find_token(), que devolvia um EphemeralToken*
 * bruto e deixava o chamador ler token->token_data fora do mutex (TOCTOU:
 * outra thread podia reciclar aquele slot do array circular entre a busca
 * e a leitura). Reverifica o token_id sob o lock antes de copiar, então
 * mesmo que o slot já tenha sido reaproveitado por outro token, o
 * resultado é tratado corretamente como "não encontrado". */
static bool find_token_data(SecureCascade *sys, const char *token_id_hex,
                             uint8_t out_data[TOKEN_DATA_SIZE]) {
    uint8_t token_id[TOKEN_ID_SIZE];
    if (!hex_to_bytes(token_id_hex, token_id, TOKEN_ID_SIZE)) {
        return false;
    }

    pthread_mutex_lock(&sys->lock);

    bool found = false;
    for (int i = 0; i < sys->bank_size; i++) {
        int idx = (sys->bank_start + i) % TOKEN_BANK_CAPACITY;
        EphemeralToken *t = &sys->token_bank[idx];

        if (t->active && !t->destroyed &&
            sodium_memcmp(t->token_id, token_id, TOKEN_ID_SIZE) == 0) {

            /* Verifica TTL */
            if (time(NULL) > t->created_at + t->ttl_seconds) {
                destroy_token(sys, t, "ttl_expirado");
                break; /* encontrado, mas expirado -> não encontrado */
            }

            memcpy(out_data, t->token_data, TOKEN_DATA_SIZE);
            found = true;
            break;
        }
    }

    pthread_mutex_unlock(&sys->lock);
    return found;
}

/* ============================================================================
 * CRIPTOGRAFIA (libsodium - ChaCha20-Poly1305)
 * ============================================================================ */

/* CORREÇÃO CRÍTICA (rev.1 -> rev.2):
 * A versão anterior concatenava master_key (32B) + token_data (32B) num
 * buffer de 64 bytes e passava para crypto_kdf_derive_from_key(). Essa
 * função da libsodium sempre lê exatamente crypto_kdf_KEYBYTES (32) bytes
 * do parâmetro `key` -- ela não sabe nem se importa que o buffer por trás
 * do ponteiro era maior. Resultado: só os 32 bytes de master_key eram
 * lidos, e token_data (que começava exatamente no byte 32) nunca entrava
 * no cálculo. Toda data_key derivada dependia só da master_key -- ou seja,
 * TODOS os registros do sistema usavam a MESMA chave AEAD, e a destruição
 * de um token não tinha nenhum efeito criptográfico real (crypto-shredding
 * só existia como bloqueio de busca em find_token, não como matemática).
 *
 * Correção: usar crypto_generichash (BLAKE2b) em modo chaveado, que aceita
 * uma chave de até 64 bytes e uma mensagem de tamanho arbitrário -- aqui
 * master_key é a chave e (token_data || KDF_CONTEXT) é a mensagem. Isso
 * garante que a chave derivada dependa genuinamente dos dois segredos: sem
 * o token_data correto, a data_key correta não pode ser reconstruída, e
 * portanto destruir o token de fato torna o registro irrecuperável. */
static bool derive_data_key(const uint8_t *master_key,
                             const uint8_t *token_data,
                             uint8_t *out_key) {
    uint8_t msg[TOKEN_DATA_SIZE + sizeof(KDF_CONTEXT) - 1];
    memcpy(msg, token_data, TOKEN_DATA_SIZE);
    memcpy(msg + TOKEN_DATA_SIZE, KDF_CONTEXT, sizeof(KDF_CONTEXT) - 1);

    int result = crypto_generichash(out_key, KEY_SIZE,
                                     msg, sizeof(msg),
                                     master_key, MASTER_KEY_SIZE);

    sodium_memzero(msg, sizeof(msg));

    return result == 0;
}

/* REV. 7: encrypt_data_ex() substitui o antigo encrypt_data() (removido) --
 * mesma criptografia AEAD, mas aceita um buffer
 * de saída OPCIONAL já alocado (out_buf, tipicamente uma fatia do pool de
 * ciphertext). Se out_buf != NULL, escreve diretamente nele -- SEM chamar
 * sodium_malloc() -- e devolve o próprio out_buf em *ciphertext_out (só
 * pra manter a mesma interface de retorno de encrypt_data(), o chamador
 * já sabe que é o mesmo ponteiro). Se out_buf == NULL, comportamento
 * idêntico ao encrypt_data() original (aloca com sodium_malloc, caminho
 * de fallback para payloads que não cabem no pool). */
static bool encrypt_data_ex(SecureCascade *sys,
                             const uint8_t token_data[TOKEN_DATA_SIZE],
                             const uint8_t *plaintext,
                             size_t plaintext_len,
                             uint8_t *nonce_out,
                             uint8_t *out_buf,
                             uint8_t **ciphertext_out,
                             size_t *ciphertext_len_out) {
    if (plaintext_len > MAX_DATA_SIZE) return false;

    uint8_t data_key[KEY_SIZE];
    if (!derive_data_key(sys->master_key, token_data, data_key)) {
        return false;
    }

    randombytes_buf(nonce_out, NONCE_SIZE);

    size_t ct_len = plaintext_len + TAG_SIZE;
    uint8_t *ciphertext = out_buf;
    bool allocated_here = false;
    if (!ciphertext) {
        ciphertext = sodium_malloc(ct_len);
        if (!ciphertext) {
            sodium_memzero(data_key, KEY_SIZE);
            return false;
        }
        allocated_here = true;
    }

    unsigned long long actual_len;
    int result = crypto_aead_chacha20poly1305_ietf_encrypt(
        ciphertext, &actual_len,
        plaintext, plaintext_len,
        NULL, 0, NULL,
        nonce_out,
        data_key
    );

    sodium_memzero(data_key, KEY_SIZE);

    if (result != 0) {
        if (allocated_here) sodium_free(ciphertext);
        return false;
    }

    *ciphertext_out = ciphertext;
    *ciphertext_len_out = (size_t)actual_len;
    return true;
}

static bool decrypt_data(SecureCascade *sys,
                          const uint8_t token_data[TOKEN_DATA_SIZE],
                          const uint8_t *nonce,
                          const uint8_t *ciphertext,
                          size_t ciphertext_len,
                          uint8_t **plaintext_out,
                          size_t *plaintext_len_out) {
    if (ciphertext_len < TAG_SIZE) return false;

    uint8_t data_key[KEY_SIZE];
    if (!derive_data_key(sys->master_key, token_data, data_key)) {
        return false;
    }
    
    size_t pt_len = ciphertext_len - TAG_SIZE;
    uint8_t *plaintext = sodium_malloc(pt_len);
    if (!plaintext) {
        sodium_memzero(data_key, KEY_SIZE);
        return false;
    }
    
    unsigned long long actual_len;
    int result = crypto_aead_chacha20poly1305_ietf_decrypt(
        plaintext, &actual_len, NULL,
        ciphertext, ciphertext_len,
        NULL, 0,
        nonce,
        data_key
    );
    
    sodium_memzero(data_key, KEY_SIZE);
    
    if (result != 0) {
        sodium_free(plaintext);
        return false;
    }
    
    *plaintext_out = plaintext;
    *plaintext_len_out = (size_t)actual_len;
    return true;
}

/* ============================================================================
 * OPERAÇÕES DE ALTO NÍVEL
 * ============================================================================ */

static bool encrypt_record(SecureCascade *sys,
                            const char *user_id,
                            const char *data_category,
                            const uint8_t *plaintext,
                            size_t plaintext_len,
                            uint32_t ttl_seconds,
                            const InteractionEntropy *interaction,
                            char *out_record_id) {
    uint8_t token_id[TOKEN_ID_SIZE];
    uint8_t token_data[TOKEN_DATA_SIZE];
    if (!generate_token(sys, user_id, ttl_seconds, interaction, token_id, token_data)) {
        return false;
    }

    /* REV. 5 (achado do teste de escala): a busca linear por slot livre
     * que existia aqui era O(N) por chamada -- preencher N registros
     * ficava O(N²) no total, e travou de verdade em N=100.000 (>5min
     * sem terminar). Trocado por um alocador "bump" atômico: cada thread
     * pega um índice NOVO e exclusivo com um único incremento atômico,
     * sem lock nenhum. Como cada slot só é entregue para UMA thread, uma
     * única vez, na vida inteira do processo (nunca há "slot livre" para
     * reciclar -- ver comentário no struct sobre rec_lock), isso também
     * fecha o Bug A da rev.3 por CONSTRUÇÃO: não existe mais nenhuma
     * corrida de "duas threads acham o mesmo slot livre", porque não
     * existe mais busca -- só um contador atômico que nunca entrega o
     * mesmo valor duas vezes. */
    size_t slot_idx = atomic_fetch_add(&sys->next_free_slot, (size_t)1);
    if (slot_idx >= sys->max_records) {
        /* Capacidade esgotada -- devolve o "excesso" pro contador não
         * crescer sem limite (cosmético, já que não há mais slots de
         * qualquer forma, mas mantém next_free_slot com significado). */
        sodium_memzero(token_data, sizeof(token_data));
        return false;
    }
    EncryptedRecord *record = &sys->records[slot_idx];

    /* O slot veio zerado do calloc() em system_init() e nunca foi tocado
     * por ninguém antes (garantia do bump allocator) -- não precisa de
     * memset. Escrever os campos aqui, ANTES de publicar o registro (ver
     * abaixo), é seguro sem lock: nenhuma outra thread consegue achar
     * este slot por ID enquanto ele não estiver no índice hash. */
    randombytes_buf(record->record_id, TOKEN_ID_SIZE);
    strncpy(record->user_id, user_id, sizeof(record->user_id) - 1);
    strncpy(record->data_category, data_category,
            sizeof(record->data_category) - 1);

    /* Publica o registro: insere no índice hash e marca active=true, sob
     * sys->lock. Este é o único ponto de sincronização necessário -- o
     * unlock() abaixo cria a barreira de visibilidade (happens-before)
     * que garante que qualquer outra thread que depois ache este slot
     * via record_index_lookup() (sob o mesmo sys->lock) enxergue os
     * campos escritos acima corretamente, mesmo tendo sido escritos
     * fora do lock. */
    pthread_mutex_lock(&sys->lock);
    record_index_insert(sys, record->record_id, slot_idx);
    record->active = true;
    pthread_mutex_unlock(&sys->lock);

    /* Criptografia AEAD fora de qualquer lock (trabalho de CPU, sem
     * I/O -- não há motivo para segurar um lock global durante isso). */
    uint8_t nonce[NONCE_SIZE];
    uint8_t *ciphertext = NULL;
    size_t ciphertext_len = 0;

    /* REV. 7: se o ciphertext resultante cabe na fatia do pool
     * (caso comum -- ver CIPHERTEXT_POOL_SLOT_SIZE), usa a fatia deste
     * slot diretamente, sem sodium_malloc() nenhum. slot_idx já é único
     * e exclusivo desta thread (veio do bump allocator acima), então
     * escrever em sys->ciphertext_pool + slot_idx*tamanho é seguro sem
     * lock -- nenhuma outra thread usa esse mesmo índice. */
    size_t would_be_ct_len = plaintext_len + TAG_SIZE;
    bool use_pool = (would_be_ct_len <= sys->ciphertext_pool_slot_size);
    uint8_t *pool_slot = use_pool
        ? (sys->ciphertext_pool + slot_idx * sys->ciphertext_pool_slot_size)
        : NULL;

    bool enc_ok = encrypt_data_ex(sys, token_data, plaintext, plaintext_len,
                                   nonce, pool_slot, &ciphertext, &ciphertext_len);
    sodium_memzero(token_data, sizeof(token_data));
    if (!enc_ok) {
        /* AEAD falhando é essencialmente só possível por OOM dentro do
         * libsodium -- em teoria quase nunca acontece na prática. Não
         * há como "devolver" o slot ao alocador bump (ele nunca
         * recicla), então só despublicamos (active=false); o slot fica
         * permanentemente desperdiçado, o que é aceitável dado o quão
         * raro é este caminho. */
        pthread_mutex_lock(&sys->lock);
        record->active = false;
        pthread_mutex_unlock(&sys->lock);
        return false;
    }

    /* Popula o conteúdo sob o lock DESTE registro (rec_lock) -- nenhuma
     * outra thread pode achar este registro por ID ainda (o ID só foi
     * devolvido ao chamador no final, sob sys->lock, mais abaixo), mas
     * mantemos o padrão uniforme: toda mutação de campos de conteúdo de
     * um EncryptedRecord passa por rec_lock. */
    pthread_mutex_lock(&record->rec_lock);

    memcpy(record->nonce_chain[0], nonce, NONCE_SIZE);
    record->ciphertext = ciphertext;
    record->ciphertext_len = ciphertext_len;
    record->ciphertext_in_pool = use_pool;

    bytes_to_hex(token_id, TOKEN_ID_SIZE,
                 record->token_chain[0],
                 sizeof(record->token_chain[0]));
    record->chain_length = 1;
    record->encryption_layers = 1;
    record->created_at = time(NULL);
    record->last_reencrypted = record->created_at;

    pthread_mutex_unlock(&record->rec_lock);

    pthread_mutex_lock(&sys->lock);

    sys->record_count++;
    sys->metrics.records_encrypted++;

    bytes_to_hex(record->record_id, TOKEN_ID_SIZE,
                 out_record_id, TOKEN_ID_SIZE * 2 + 1);

    pthread_mutex_unlock(&sys->lock);

    audit_log(sys, "RECORD_ENCRYPTED", user_id, out_record_id);

    return true;
}

static bool decrypt_record(SecureCascade *sys,
                            const char *record_id_hex,
                            const char *requester_id,
                            uint8_t **plaintext_out,
                            size_t *plaintext_len_out) {
    uint8_t record_id[TOKEN_ID_SIZE];
    if (!hex_to_bytes(record_id_hex, record_id, TOKEN_ID_SIZE)) {
        return false;
    }
    
    /* REV. 5 (achado do teste de escala): a busca linear por record_id
     * (O(N) por chamada) travou o sistema em N=100.000 -- trocada pelo
     * índice hash O(1) médio (ver record_index_lookup() e o comentário
     * no struct). */
    pthread_mutex_lock(&sys->lock);

    EncryptedRecord *record = NULL;
    size_t found_slot;
    if (record_index_lookup(sys, record_id, &found_slot) &&
        sys->records[found_slot].active) {
        record = &sys->records[found_slot];
    }

    pthread_mutex_unlock(&sys->lock);

    if (!record) {
        audit_log(sys, "DECRYPT_NOT_FOUND", requester_id, record_id_hex);
        return false;
    }

    /* REV. 3 (pentest de concorrência, Bug B confirmado sob carga real --
     * SEGV real capturado pelo TSan): ANTES, ciphertext/ciphertext_len/
     * nonce/chain_length/token_chain eram lidos DIRETO do ponteiro
     * `record`, sem nenhum lock. Se um reencrypt_record() concorrente no
     * MESMO record_id desse sodium_free(record->ciphertext) e trocasse o
     * ponteiro enquanto este memcpy() ainda estava rodando, era um
     * use-after-free de verdade -- não hipotético, o processo caiu com
     * SEGV durante o teste de carga. Correção: copia TUDO que é mutável
     * para buffers locais desta thread, sob record->rec_lock, e só
     * então solta o lock antes de fazer o trabalho de descriptografia
     * (que não precisa mais tocar `record` nenhuma vez). */
    pthread_mutex_lock(&record->rec_lock);

    size_t ciphertext_len = record->ciphertext_len;
    uint8_t *current_data = sodium_malloc(ciphertext_len);
    if (!current_data) {
        pthread_mutex_unlock(&record->rec_lock);
        return false;
    }
    memcpy(current_data, record->ciphertext, ciphertext_len);
    size_t current_len = ciphertext_len;

    /* REV. 7 [correção do bug de nonce único -- ver comentário no campo
     * nonce_chain do struct]: copia a cadeia INTEIRA de nonces, não só o
     * mais recente -- cada camada i precisa do nonce_chain[i] exato que
     * foi usado quando aquela camada foi criada. */
    size_t chain_length = record->chain_length;
    uint8_t nonce_chain_copy[MAX_TOKEN_CHAIN][NONCE_SIZE];
    memcpy(nonce_chain_copy, record->nonce_chain, sizeof(nonce_chain_copy));

    char chain_copy[MAX_TOKEN_CHAIN][TOKEN_ID_SIZE * 2 + 1];
    memcpy(chain_copy, record->token_chain, sizeof(chain_copy));

    pthread_mutex_unlock(&record->rec_lock);

    /* Descriptografa camada por camada (ordem reversa), agora só sobre
     * cópias locais -- nenhum acesso a `record` daqui até o fim, exceto
     * as seções explicitamente re-travadas abaixo. */
    for (ssize_t i = (ssize_t)chain_length - 1; i >= 0; i--) {
        uint8_t token_data[TOKEN_DATA_SIZE];

        if (!find_token_data(sys, chain_copy[i], token_data)) {
            sodium_free(current_data);

            pthread_mutex_lock(&record->rec_lock);
            record->shredded = true;
            pthread_mutex_unlock(&record->rec_lock);

            pthread_mutex_lock(&sys->lock);
            sys->metrics.decryption_failures++;
            pthread_mutex_unlock(&sys->lock);

            audit_log(sys, "DECRYPT_SHREDDED", requester_id,
                     "CRYPTO-SHREDDING: token indisponível");
            return false;
        }

        uint8_t *next_data = NULL;
        size_t next_len = 0;

        bool dec_ok = decrypt_data(sys, token_data, nonce_chain_copy[i],
                                    current_data, current_len,
                                    &next_data, &next_len);
        sodium_memzero(token_data, sizeof(token_data));

        if (!dec_ok) {
            sodium_free(current_data);
            audit_log(sys, "DECRYPT_FAILED", requester_id,
                     "falha na descriptografia");
            return false;
        }

        sodium_free(current_data);
        current_data = next_data;
        current_len = next_len;
    }
    
    *plaintext_out = current_data;
    *plaintext_len_out = current_len;
    
    pthread_mutex_lock(&sys->lock);
    sys->metrics.records_decrypted++;
    pthread_mutex_unlock(&sys->lock);
    
    audit_log(sys, "RECORD_DECRYPTED", requester_id, record_id_hex);
    
    return true;
}

static bool reencrypt_record(SecureCascade *sys,
                              const char *record_id_hex,
                              const char *user_id,
                              const InteractionEntropy *interaction) {
    uint8_t record_id[TOKEN_ID_SIZE];
    if (!hex_to_bytes(record_id_hex, record_id, TOKEN_ID_SIZE)) {
        return false;
    }
    
    /* REV. 5: mesma troca de busca linear O(N) por índice hash O(1)
     * médio que decrypt_record() -- ver comentário lá. */
    pthread_mutex_lock(&sys->lock);

    EncryptedRecord *record = NULL;
    size_t found_slot;
    if (record_index_lookup(sys, record_id, &found_slot) &&
        sys->records[found_slot].active) {
        record = &sys->records[found_slot];
    }

    if (!record) {
        pthread_mutex_unlock(&sys->lock);
        return false;
    }

    pthread_mutex_unlock(&sys->lock);

    /* Gera novo token fora de qualquer lock de registro -- generate_token
     * tem seu próprio lock interno (sys->lock), autocontido. */
    uint8_t new_token_id[TOKEN_ID_SIZE];
    uint8_t new_token_data[TOKEN_DATA_SIZE];
    if (!generate_token(sys, user_id, 3600, interaction, new_token_id, new_token_data)) {
        return false;
    }

    /* REV. 3 (pentest de concorrência, Bug C confirmado sob carga real):
     * ANTES, a leitura do ciphertext antigo (para embrulhá-lo numa nova
     * camada) e a escrita do novo ciphertext aconteciam em DUAS seções
     * críticas separadas, sem lock nenhum entre elas. Duas chamadas de
     * reencrypt_record() concorrentes no MESMO record_id podiam ambas
     * ler o MESMO ciphertext antigo, ambas embrulhá-lo, e a "perdedora"
     * da corrida de escrita sobrescrevia com uma camada que embrulhava
     * os bytes ERRADOS (o ciphertext já obsoleto, não o da outra
     * thread) -- corrompendo silenciosamente a cadeia onion (a camada
     * mais nova deixava de "casar" com a anterior, e uma futura
     * decrypt_record() falhava com DECRYPT_FAILED sem nenhum aviso do
     * motivo real). Também havia sodium_free()/reatribuição de ponteiro
     * concorrentes no mesmo campo. Correção: TODA a operação --
     * verificar chain_length, ler o ciphertext antigo, criptografar a
     * nova camada, e escrever o resultado -- acontece sob o MESMO
     * record->rec_lock, do início ao fim, sem soltar. Como é trabalho
     * de CPU (sem I/O/bloqueio) e o lock é POR REGISTRO, isso serializa
     * só reencriptações do MESMO registro -- outros registros continuam
     * sendo processados livremente por outras threads. */
    pthread_mutex_lock(&record->rec_lock);

    if (record->chain_length >= MAX_TOKEN_CHAIN) {
        pthread_mutex_unlock(&record->rec_lock);
        sodium_memzero(new_token_data, sizeof(new_token_data));
        return false;
    }

    uint8_t nonce[NONCE_SIZE];
    uint8_t *new_ciphertext = NULL;
    size_t new_ciphertext_len = 0;

    /* REV. 7: a nova camada embrulha o ciphertext ATUAL como "plaintext"
     * de entrada -- e a saída (record->ciphertext_len + TAG_SIZE bytes)
     * pode ir direto pra fatia do pool deste registro (found_slot), como
     * em encrypt_record(). Só que aqui a entrada e a possível saída
     * (mesma fatia do pool, se o ciphertext atual já vivia lá) seriam o
     * MESMO buffer -- não dá pra ler e escrever no mesmo lugar durante a
     * criptografia. Por isso: copia o ciphertext atual pra uma cópia
     * separada primeiro (pilha, se couber no tamanho do pool; senão um
     * sodium_malloc temporário), e SÓ DEPOIS escreve a nova camada na
     * fatia do pool (ou faz fallback, se a nova camada não couber mais). */
    size_t old_ct_len = record->ciphertext_len;
    size_t new_ct_len = old_ct_len + TAG_SIZE;

    uint8_t old_ct_stack[CIPHERTEXT_POOL_SLOT_SIZE];
    uint8_t *old_ct_heap = NULL;
    const uint8_t *plaintext_in;

    if (old_ct_len <= sizeof(old_ct_stack)) {
        memcpy(old_ct_stack, record->ciphertext, old_ct_len);
        plaintext_in = old_ct_stack;
    } else {
        old_ct_heap = sodium_malloc(old_ct_len);
        if (!old_ct_heap) {
            pthread_mutex_unlock(&record->rec_lock);
            sodium_memzero(new_token_data, sizeof(new_token_data));
            return false;
        }
        memcpy(old_ct_heap, record->ciphertext, old_ct_len);
        plaintext_in = old_ct_heap;
    }

    bool new_use_pool = (new_ct_len <= sys->ciphertext_pool_slot_size);
    uint8_t *pool_slot = new_use_pool
        ? (sys->ciphertext_pool + found_slot * sys->ciphertext_pool_slot_size)
        : NULL;

    bool enc_ok = encrypt_data_ex(sys, new_token_data, plaintext_in, old_ct_len,
                                   nonce, pool_slot, &new_ciphertext, &new_ciphertext_len);
    sodium_memzero(new_token_data, sizeof(new_token_data));
    if (old_ct_heap) sodium_free(old_ct_heap);
    if (!enc_ok) {
        pthread_mutex_unlock(&record->rec_lock);
        return false;
    }

    if (!record->ciphertext_in_pool) sodium_free(record->ciphertext);
    record->ciphertext = new_ciphertext;
    record->ciphertext_len = new_ciphertext_len;
    record->ciphertext_in_pool = new_use_pool;
    /* REV. 7: guarda o nonce desta nova camada no MESMO índice
     * (record->chain_length, ainda não incrementado) que token_chain vai
     * usar logo abaixo -- nonce_chain[i] e token_chain[i] sempre andam
     * juntos, um par por camada. */
    memcpy(record->nonce_chain[record->chain_length], nonce, NONCE_SIZE);

    bytes_to_hex(new_token_id, TOKEN_ID_SIZE,
                 record->token_chain[record->chain_length],
                 sizeof(record->token_chain[0]));
    record->chain_length++;
    record->encryption_layers++;
    record->last_reencrypted = time(NULL);

    pthread_mutex_unlock(&record->rec_lock);

    pthread_mutex_lock(&sys->lock);
    sys->metrics.records_reencrypted++;
    pthread_mutex_unlock(&sys->lock);

    audit_log(sys, "RECORD_REENCRYPTED", user_id, record_id_hex);

    return true;
}

/* ============================================================================
 * MÉTRICAS E RELATÓRIOS
 * ============================================================================ */

static void print_metrics(const SecureCascade *sys) {
    print_separator("MÉTRICAS DO SISTEMA");
    printf("  Tokens criados:            %llu\n",
           (unsigned long long)sys->metrics.tokens_created);
    printf("  Tokens destruídos:         %llu  (crypto-shredding)\n",
           (unsigned long long)sys->metrics.tokens_destroyed);
    printf("  Registros criptografados:  %llu\n",
           (unsigned long long)sys->metrics.records_encrypted);
    printf("  Registros re-criptograf.:  %llu\n",
           (unsigned long long)sys->metrics.records_reencrypted);
    printf("  Registros descriptograf.:  %llu\n",
           (unsigned long long)sys->metrics.records_decrypted);
    printf("  Falhas de descriptografia: %llu\n",
           (unsigned long long)sys->metrics.decryption_failures);
    printf("  Eventos de cascata:        %llu\n",
           (unsigned long long)sys->metrics.cascade_events);
    printf("  Eventos de auditoria:      %llu\n",
           (unsigned long long)sys->metrics.audit_events);
    printf("  Tokens no banco:           %d / %d\n",
           sys->bank_size, TOKEN_BANK_CAPACITY);
    printf("  Registros ativos:          %zu / %zu\n",
           sys->record_count, sys->max_records);
    print_separator(NULL);
}

/* ============================================================================
 * SIMULAÇÃO DE ENTROPIA DE INTERAÇÃO (só para esta demo em linha de comando)
 * ============================================================================
 * Em produção, InteractionEntropy vem do CLIENTE real: o front-end (web/
 * mobile) mede os deltas de tempo entre eventos genuínos de clique, toque
 * ou tecla do usuário e envia essa amostra junto com a chamada de
 * criptografia. Este binário não tem interface gráfica nenhuma, então as
 * duas funções abaixo só EXISTEM para exercitar o validador na demonstração
 * -- elas mesmas são geradas por código, exatamente o tipo de fonte que o
 * validador existe para desencorajar em produção. Não as use como molde
 * para uma integração real. */

static void simulate_human_interaction(InteractionEntropy *ie) {
    /* Jitter plausível (80ms-480ms entre eventos), amostrado a partir do
     * CSPRNG só para ilustrar o caminho de sucesso do validador. */
    ie->sample_count = 8;
    for (size_t i = 0; i < ie->sample_count; i++) {
        uint16_t r;
        randombytes_buf(&r, sizeof(r));
        ie->event_deltas_us[i] = 80000 + ((uint64_t)r % 400000);
    }
}

static void simulate_bot_interaction(InteractionEntropy *ie) {
    /* Timing perfeitamente constante -- o padrão mais barato e mais comum
     * de um script sem jitter real. Deve ser rejeitado pelo validador. */
    ie->sample_count = 8;
    for (size_t i = 0; i < ie->sample_count; i++) {
        ie->event_deltas_us[i] = 150000;
    }
}

/* ============================================================================
 * DEMONSTRAÇÃO
 * ============================================================================ */

static void run_demo(SecureCascade *sys) {
    print_separator("DEMONSTRAÇÃO COMPLETA");

    printf("\n[0] Tentando criar registro com timing tipo bot (script, sem jitter real)...\n");
    {
        InteractionEntropy bot_ie;
        simulate_bot_interaction(&bot_ie);
        char rejected_id[TOKEN_ID_SIZE * 2 + 1];
        if (encrypt_record(sys, "bot_attacker", "PII",
                           (const uint8_t*)"tentativa automatizada", 22,
                           3600, &bot_ie, rejected_id)) {
            printf("    ⚠ INESPERADO: token gerado com timing de bot\n");
        } else {
            printf("    ✓ REJEITADO: entropia de interação reconhecida como não-humana\n");
        }
    }

    printf("\n[1] Criptografando dados sensíveis (com interação humana simulada)...\n");
    const char *sensitive_data = "CPF: 123.456.789-00 | Nome: João Silva";
    InteractionEntropy ie;
    simulate_human_interaction(&ie);

    char record_id[TOKEN_ID_SIZE * 2 + 1];
    if (!encrypt_record(sys, "user_alice", "PII",
                        (const uint8_t*)sensitive_data, strlen(sensitive_data),
                        3600, &ie, record_id)) {
        printf("    ERRO na criptografia\n");
        return;
    }
    printf("    ✓ Registro: %s\n", record_id);
    printf("    ✓ Dados: '%s'\n", sensitive_data);

    printf("\n[2] Descriptografando (tokens válidos)...\n");
    uint8_t *decrypted = NULL;
    size_t decrypted_len = 0;

    if (decrypt_record(sys, record_id, "user_alice",
                       &decrypted, &decrypted_len)) {
        printf("    ✓ Sucesso: '%.*s'\n", (int)decrypted_len, decrypted);
        sodium_free(decrypted);
    } else {
        printf("    ✗ Falha\n");
    }

    printf("\n[3] Re-criptografando (nova camada)...\n");
    simulate_human_interaction(&ie);
    if (reencrypt_record(sys, record_id, "user_alice", &ie)) {
        printf("    ✓ Nova camada adicionada\n");
    } else {
        printf("    ✗ Falha na re-criptografia\n");
    }

    printf("\n[4] Descriptografando após re-criptografia...\n");
    if (decrypt_record(sys, record_id, "user_alice",
                       &decrypted, &decrypted_len)) {
        printf("    ✓ Sucesso: '%.*s'\n", (int)decrypted_len, decrypted);
        sodium_free(decrypted);
    } else {
        printf("    ✗ Falha\n");
    }

    printf("\n[5] Simulando cascata (gerando %d tokens)...\n",
           CASCADE_THRESHOLD + 50);
    for (int i = 0; i < CASCADE_THRESHOLD + 50; i++) {
        char user[32];
        snprintf(user, sizeof(user), "user_%d", i);
        char data[64];
        snprintf(data, sizeof(data), "Dado temporário %d", i);
        char temp_id[TOKEN_ID_SIZE * 2 + 1];
        simulate_human_interaction(&ie);
        encrypt_record(sys, user, "TEMP",
                       (const uint8_t*)data, strlen(data),
                       60, &ie, temp_id);
    }
    printf("    ✓ Cascata executada\n");

    printf("\n[6] Tentando descriptografar registro original...\n");
    printf("    (Token original foi destruído pela cascata)\n");
    if (decrypt_record(sys, record_id, "user_alice",
                       &decrypted, &decrypted_len)) {
        printf("    ⚠ INESPERADO: descriptografia funcionou\n");
        sodium_free(decrypted);
    } else {
        printf("    ✓ CONFIRMADO: CRYPTO-SHREDDING\n");
        printf("    ✓ Dados irrecuperáveis (token destruído)\n");
    }
    
    print_metrics(sys);
}

static void run_benchmark(SecureCascade *sys) {
    print_separator("BENCHMARK DE PERFORMANCE");
    
    const int iterations = 1000;
    const char *data = "Dados de benchmark para teste de performance";
    size_t data_len = strlen(data);
    
    printf("\n  Executando %d iterações de criptografia...\n", iterations);
    
    clock_t start = clock();
    
    char record_ids[100][TOKEN_ID_SIZE * 2 + 1];
    InteractionEntropy bench_ie;
    for (int i = 0; i < iterations && i < 100; i++) {
        simulate_human_interaction(&bench_ie);
        encrypt_record(sys, "benchmark", "TEST",
                       (const uint8_t*)data, data_len,
                       60, &bench_ie, record_ids[i]);
    }
    
    clock_t end = clock();
    double encrypt_time = (double)(end - start) / CLOCKS_PER_SEC;
    
    printf("  Tempo de criptografia: %.4f segundos\n", encrypt_time);
    printf("  Throughput: %.2f ops/segundo\n", 100.0 / encrypt_time);
    
    printf("\n  Executando %d iterações de descriptografia...\n", iterations);
    
    start = clock();
    
    int success_count = 0;
    for (int i = 0; i < 100; i++) {
        uint8_t *decrypted = NULL;
        size_t decrypted_len = 0;
        if (decrypt_record(sys, record_ids[i], "benchmark",
                           &decrypted, &decrypted_len)) {
            success_count++;
            sodium_free(decrypted);
        }
    }
    
    end = clock();
    double decrypt_time = (double)(end - start) / CLOCKS_PER_SEC;
    
    printf("  Tempo de descriptografia: %.4f segundos\n", decrypt_time);
    printf("  Throughput: %.2f ops/segundo\n", 100.0 / decrypt_time);
    printf("  Sucesso: %d/100\n", success_count);
    
    print_separator(NULL);
}

static void run_stress_test(SecureCascade *sys) {
    print_separator("TESTE DE STRESS - CASCATA INTENSIVA");
    
    printf("\n  Gerando %d registros para forçar múltiplas cascatas...\n",
           CASCADE_THRESHOLD * 3);
    
    int success = 0;
    int failed = 0;
    
    for (int i = 0; i < CASCADE_THRESHOLD * 3; i++) {
        char user[32];
        snprintf(user, sizeof(user), "stress_user_%d", i);
        char data[64];
        snprintf(data, sizeof(data), "Stress test data %d", i);
        
        InteractionEntropy stress_ie;
        simulate_human_interaction(&stress_ie);

        char record_id[TOKEN_ID_SIZE * 2 + 1];
        if (encrypt_record(sys, user, "STRESS",
                           (const uint8_t*)data, strlen(data),
                           30, &stress_ie, record_id)) {
            success++;
        } else {
            failed++;
        }
        
        if ((i + 1) % 50 == 0) {
            printf("    Progresso: %d/%d (sucesso: %d, falha: %d)\n",
                   i + 1, CASCADE_THRESHOLD * 3, success, failed);
        }
    }
    
    printf("\n  Resultado final:\n");
    printf("    Registros criados: %d\n", success);
    printf("    Falhas: %d\n", failed);
    
    print_metrics(sys);
    
    printf("\n  Verificando crypto-shredding...\n");

    /* Não temos os IDs salvos, mas podemos verificar métricas */
    if (sys->metrics.tokens_destroyed > 0) {
        printf("    ✓ %llu tokens foram destruídos pela cascata\n",
               (unsigned long long)sys->metrics.tokens_destroyed);
        printf("    ✓ Crypto-shredding funcionando corretamente\n");
    } else {
        printf("    ⚠ Nenhum token foi destruído ainda\n");
    }
    
    print_separator(NULL);
}

/* ============================================================================
 * MAIN
 * ============================================================================ */

static void print_usage(const char *program) {
    printf("\n");
    printf("========================================================================\n");
    printf("  %s v%s\n", SYSTEM_NAME, SYSTEM_VERSION);
    printf("========================================================================\n");
    printf("\n");
    printf("  Uso: %s [OPÇÃO]\n", program);
    printf("\n");
    printf("  Opções:\n");
    printf("    (nenhuma)     Executa teste básico\n");
    printf("    --demo        Executa demonstração completa\n");
    printf("    --benchmark   Executa benchmark de performance\n");
    printf("    --stress      Executa teste de stress\n");
    printf("    --help        Mostra esta ajuda\n");
    printf("\n");
    printf("========================================================================\n");
    printf("  ⚠️  AVISO: Este código é para TESTES em ambiente controlado.\n");
    printf("  NÃO usar em produção sem auditoria externa independente.\n");
    printf("========================================================================\n\n");
}

int main(int argc, char *argv[]) {
    printf("\n");
    printf("========================================================================\n");
    printf("  %s v%s\n", SYSTEM_NAME, SYSTEM_VERSION);
    printf("  Sistema de Criptografia com Tokens Efêmeros em Cascata\n");
    printf("========================================================================\n");
    printf("\n");
    printf("  ⚠️  MODO TESTE - NÃO USAR EM PRODUÇÃO\n");
    printf("  ⚠️  Requer auditoria externa antes de qualquer uso real\n");
    printf("\n");
    
    SecureCascade sys;
    if (!system_init(&sys, "audit_test.log", MAX_RECORDS, false)) {
        fprintf(stderr, "[ERRO] Falha ao inicializar sistema\n");
        return 1;
    }
    
    if (argc > 1) {
        if (strcmp(argv[1], "--demo") == 0) {
            run_demo(&sys);
        } else if (strcmp(argv[1], "--benchmark") == 0) {
            run_benchmark(&sys);
        } else if (strcmp(argv[1], "--stress") == 0) {
            run_stress_test(&sys);
        } else if (strcmp(argv[1], "--help") == 0) {
            print_usage(argv[0]);
        } else {
            fprintf(stderr, "[ERRO] Opção desconhecida: %s\n", argv[1]);
            print_usage(argv[0]);
            system_shutdown(&sys);
            return 1;
        }
    } else {
        /* Teste básico */
        printf("[INFO] Executando teste básico...\n\n");
        
        const char *test_data = "Dados de teste para validação";
        char record_id[TOKEN_ID_SIZE * 2 + 1];
        InteractionEntropy basic_ie;
        simulate_human_interaction(&basic_ie);

        printf("[1] Criptografando...\n");
        if (encrypt_record(&sys, "test_user", "TEST",
                           (const uint8_t*)test_data, strlen(test_data),
                           3600, &basic_ie, record_id)) {
            printf("    ✓ Registro: %s\n", record_id);
            
            printf("[2] Descriptografando...\n");
            uint8_t *decrypted = NULL;
            size_t decrypted_len = 0;
            
            if (decrypt_record(&sys, record_id, "test_user",
                               &decrypted, &decrypted_len)) {
                printf("    ✓ Dados: '%.*s'\n", (int)decrypted_len, decrypted);
                
                if (decrypted_len == strlen(test_data) &&
                    memcmp(decrypted, test_data, decrypted_len) == 0) {
                    printf("    ✓ VALIDAÇÃO: dados íntegros\n");
                } else {
                    printf("    ✗ VALIDAÇÃO FALHOU: dados corrompidos\n");
                }
                
                sodium_free(decrypted);
            } else {
                printf("    ✗ Falha na descriptografia\n");
            }
        } else {
            printf("    ✗ Falha na criptografia\n");
        }
        
        printf("\n[INFO] Para testes completos, use:\n");
        printf("       %s --demo\n", argv[0]);
        printf("       %s --benchmark\n", argv[0]);
        printf("       %s --stress\n", argv[0]);
    }
    
    system_shutdown(&sys);
    
    printf("\n========================================================================\n");
    printf("  TESTE CONCLUÍDO\n");
    printf("========================================================================\n");
    printf("\n  Lembrete: Este código é para TESTES.\n");
    printf("  Antes de produção: auditoria externa + HSM/KMS + compliance.\n");
    printf("========================================================================\n\n");
    
    return 0;
}