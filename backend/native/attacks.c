#include <string.h>

/* ---------------------------------------------------------------- force brute --
 * Parcourt charset^length dans l'ordre lexicographique (odometre : le dernier
 * caractere tourne le plus vite), jusqu'a tomber sur `target` ou epuiser
 * l'espace / la limite de tentatives / etre interrompue.
 *
 * Retour : 1 = trouee (rang 1-based ecrit dans *out_rank) ;
 *          0 = espace epuise ou limite atteinte ;
 *         -1 = interrompue par *stop_flag.
 * *pos = essais reellement effectues (mis a jour tous les `report_every`,
 * et a la sortie, quelle qu'elle soit). */
int brute_search(const char *charset, int charset_len, int length,
                  const char *target, int target_len,
                  long long limit, long long report_every,
                  volatile long long *pos, volatile int *stop_flag,
                  long long *out_rank)
{
    if (length <= 0 || length > 64 || target_len != length) { *pos = 0; return 0; }

    int idx[64];
    char buf[65];
    for (int i = 0; i < length; i++) idx[i] = 0;
    buf[length] = '\0';

    long long attempts = 0;
    for (;;) {
        attempts++;
        for (int i = 0; i < length; i++) buf[i] = charset[idx[i]];

        if (memcmp(buf, target, length) == 0) {
            *pos = attempts;
            *out_rank = attempts;
            return 1;
        }
        if (attempts % report_every == 0) {
            *pos = attempts;
            if (*stop_flag) return -1;
        }
        if (limit > 0 && attempts >= limit) { *pos = attempts; return 0; }

        /* incremente l'odometre */
        int i = length - 1;
        while (i >= 0) {
            idx[i]++;
            if (idx[i] < charset_len) break;
            idx[i] = 0;
            i--;
        }
        if (i < 0) { *pos = attempts; return 0; }   /* espace epuise */
    }
}

/* ------------------------------------------------------------ dictionnaire --
 * Parcourt un buffer de mots separes par '\n' (un fichier du dictionnaire,
 * deja decompresse cote Python) a la recherche de `target`.
 *
 * `base` : nombre de mots deja parcourus dans les fichiers precedents — permet
 * a *pos de rester une progression continue d'un fichier a l'autre, sans que
 * Python ait a tout recharger en memoire d'un coup.
 *
 * Retour : 1 = trouvee (position 1-based DANS CE BUFFER dans *out_rank) ;
 *          0 = buffer epuise ou limite atteinte ; -1 = interrompue.
 * *pos = base + mots parcourus dans ce buffer. */
int dict_search_buffer(const char *buf, long long buf_len,
                        const char *target, int target_len,
                        long long limit, long long base, long long report_every,
                        volatile long long *pos, volatile int *stop_flag,
                        long long *out_rank)
{
    long long i = 0;
    long long word_no = 0;
    while (i < buf_len) {
        long long start = i;
        while (i < buf_len && buf[i] != '\n') i++;
        long long len = i - start;
        if (len > 0) {
            word_no++;
            if (len == target_len && memcmp(buf + start, target, target_len) == 0) {
                *pos = base + word_no;
                *out_rank = word_no;
                return 1;
            }
            if (word_no % report_every == 0) {
                *pos = base + word_no;
                if (*stop_flag) return -1;
            }
            if (limit > 0 && base + word_no >= limit) { *pos = base + word_no; return 0; }
        }
        i++;   /* saute le '\n' */
    }
    *pos = base + word_no;
    return 0;
}
