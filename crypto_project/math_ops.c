// ----- math_ops.c -----
#include "math_ops.h"

int add(int a, int b) {
    return a + b;
}

int sub(int a, int b) {
    return a - b;
}

int mul(int a, int b) {
    return a * b;
}

double divide(int a, int b) {
    return b != 0 ? (double)a / b : 0.0;
}

int gcd(int a, int b) {
    if (b == 0) return a > 0 ? a : -a;
    return gcd(b, a % b);
}

int factorial(int n) {
    if (n < 0) return 0;
    int f = 1;
    for (int i = 2; i <= n; i++)
        f *= i;
    return f;
}