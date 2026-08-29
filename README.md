# SecureCascade

Sistema de criptografia em C (libsodium) baseado no conceito de **Wall of Entropy**: um buffer circular de tokens efemeros que expiram com o tempo, disparando *crypto-shredding* automatico dos dados que dependem deles.

## Como funciona

- Buffer circular de tokens efemeros (a "parede de entropia") fornece o material usado para derivar as chaves de cada registro.
- Cada registro pode ser re-criptografado em camadas sucessivas (estilo onion/AEAD), cada camada com seu proprio nonce.
- Quando um token expira e e sobrescrito no buffer circular, os dados que dependiam dele se tornam irrecuperaveis (crypto-shredding).

## Destaques tecnicos

- AEAD: `crypto_aead_chacha20poly1305_ietf_*` (libsodium)
- Hash: `crypto_generichash` (BLAKE2b)
- Pool de memoria em arena para o ciphertext (uma unica alocacao `sodium_malloc` fatiada em slots), reduzindo o overhead por registro de ~20KB para ~1.4KB
- Testado com AddressSanitizer, UndefinedBehaviorSanitizer e ThreadSanitizer
- Escala testada empiricamente: ~4,2 milhoes de registros concorrentes dentro de um limite de 5.83GB de RAM

## Build

```
gcc -O2 -Wall -Wextra securecascade.c -o securecascade -lsodium -lpthread
```

## Uso

```
./securecascade --demo
./securecascade --benchmark
./securecascade --stress
```

## Aviso

Projeto experimental/educacional, em desenvolvimento ativo. Nao use em producao sem auditoria de seguranca independente.

## Licenca

MIT
