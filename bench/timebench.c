#include <sys/time.h>

#include <stdio.h>
#include <stdlib.h>

#include <rho/rho.h>

/*
 * The program calculates how long (wall clock time)
 * it takes to make n number of calls to gettimeofday(2),
 * where n is a command-line argument
 */

#define DEFAULT_RUNS 10

static int
timeval_cmp(const void *a, const void *b)
{
    return (rho_timeval_cmp(a, b));
}

int 
main(int argc, char *argv[])
{
    int i = 0;
    int j = 0;
    int n = 0;
    struct timeval start;
    struct timeval tmp;
    struct timeval end;
    struct timeval elapsed;
    struct timeval results[DEFAULT_RUNS];
    double sum = 0.0;


    if (argc != 2) {
        fprintf(stderr, "usage: %s ITERATIONS\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    n = rho_str_toint(argv[1], 10);

    for (i = 0; i < DEFAULT_RUNS; i++) {
        (void)gettimeofday(&start, NULL);
        for (j = 0; j < n; j++) {
            (void)gettimeofday(&tmp, NULL);
        }
        (void)gettimeofday(&end, NULL);
        rho_timeval_subtract(&end, &start, &elapsed);
        results[i] = elapsed;
        printf("calls: %d, elapsed: secs:%ld, usec:%ld\n",
            n, (long)elapsed.tv_sec, (long)elapsed.tv_usec);
    }

    /*
     * 30% trimmed
     */
    qsort(results, DEFAULT_RUNS, sizeof(struct timeval), timeval_cmp);
    for (i = 3; i < 7; i++) {
        printf("elapsed: secs:%ld, usec:%ld\n",
                results[i].tv_sec, results[i].tv_usec);
        sum += rho_timeval_to_sec_double(&results[i]);
    }

    sum /= 4.0;
    printf("trimmed mean: %lf s for %d calls (%.9f s/rpc)\n",
            sum, n, sum / (1.0 * n));

    return (0);
}
