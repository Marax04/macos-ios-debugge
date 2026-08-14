int __fastcall sub_140052F60(__int64 *a1, __int64 a2, size_t a3, size_t a4) {
    int v_20;
    int v_28;
    int result;
    int v3;
    int v4;
    int v2;

    v_20 = (int)a1;
    v_28 = a2;
    if (a2 == 0) {
        result = 0;
    } else {
        a2 += (__int64)a1;
        result = 0;
        a3 = 0;
        do {
            a4 = *a1;
            a4 += 208;
            if (a4 >= 10) JUMPOUT(0x140052ff0);
            if (a3 >= 9) {
                ++a1;
                ++a3;
                return a3;
            }
            v3 = 1;
            if (a3 == 8) {
                a4 *= v3;
                result += a4;
                return result;
            }
            v4 = 8;
            v4 -= a3;
            v2 = 10;
            do {
                v4 >>= 1;
                v2 *= v2;
            } while (true);
        } while (a1 != a2);
    }
    return result;
}