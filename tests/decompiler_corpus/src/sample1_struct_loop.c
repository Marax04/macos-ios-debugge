#include <stdint.h>
#include <stddef.h>

/* Exercises: struct field recovery (pt->x/->y/->sum), semantic variable
 * naming (total, count, i), loop-flag conditions (i < n). */

typedef struct Point {
    int64_t x;
    int64_t y;
    int64_t sum;
} Point;

int64_t accumulate(Point *pts, int n) {
    int64_t total = 0;
    for (int i = 0; i < n; i++) {
        pts[i].sum = pts[i].x + pts[i].y;
        total += pts[i].sum;
    }
    return total;
}

int64_t find_max(const int64_t *arr, size_t len) {
    int64_t best = arr[0];
    for (size_t i = 1; i < len; i++) {
        if (arr[i] > best) {
            best = arr[i];
        }
    }
    return best;
}

int main(void) {
    Point pts[3] = {{1, 2, 0}, {3, 4, 0}, {5, 6, 0}};
    int64_t t = accumulate(pts, 3);
    int64_t arr[4] = {10, 40, 20, 30};
    int64_t m = find_max(arr, 4);
    return (int)(t + m);
}
