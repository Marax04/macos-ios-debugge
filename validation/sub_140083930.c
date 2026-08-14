__int64 sub_1400831E0();

__int64 __fastcall sub_140083930(__int64 a1, int a2, size_t a3, int a4) {
    __int64 rsp;
    int v_20;
    int v_30;
    int v_38;
    int v_40;
    int v_41;
    int v_42;
    int v_44;
    int v_4c;
    int v_50;
    int v_90;
    __int64 *dst;
    __int64 result;
    __int64 v4;
    __int64 v2;
    int v5;

    dst = (__int64 *)a3;
    v_20 = 1;
    a1 = rsp + 64;
    sub_1400831E0(a1, a1, a2);
    a2 = v_40;
    result = v_41;
    a1 = v_42;
    if (a2 != 4) {
        v4 = v_90;
        a3 = v_4c;
        v_38 = a3;
        v2 = v_44;
        v_30 = v2;
        v5 = v_50;
        a3 = (v2 == 5) ? 1 : 0;
        v5 &= 15;
        a4 = a3;
        a4 <<= 4;
        a4 |= v5;
        a3 |= 4;
        a4 += 16;
        if (v4 == 0) {
            v4 = *(dst + 64);
            if (v4 <= 3) {
                v4 <<= 4;
                *(dst + v4) = 0;
                *(dst + v4 + 1) = a3;
                *(dst + v4 + 2) = a4;
                a3 = *(dst + 64);
                ++a3;
                *(dst + 64) = a3;
                if (a3 <= 3) {
                    a3 <<= 4;
                    *(dst + v2) = a2;
                    *(dst + v2 + 1) = result;
                    *(dst + v2 + 2) = a1;
                    result = v_30;
                    *(dst + v2 + 4) = result;
                    result = v_38;
                    *(dst + v2 + 12) = result;
                    *(dst + 64) = *(dst + 64) + 1;
                }
            }
        } else {
            v4 = *(dst + 64);
            if (v4 <= 3) {
                v4 <<= 4;
                *(dst + v4) = a2;
                *(dst + v4 + 1) = result;
                *(dst + v4 + 2) = a1;
                result = v_30;
                *(dst + v4 + 4) = result;
                result = v_38;
                *(dst + v4 + 12) = result;
                result = *(dst + 64);
                ++result;
                *(dst + 64) = result;
                if (result <= 3) {
                    result <<= 4;
                    *(dst + result) = 0;
                    *(dst + result + 1) = a3;
                    *(dst + result + 2) = a4;
                    return result;
                }
            }
        }
        result = 6;
    }
    a1 <<= 8;
    result |= a1;
    return result;
}