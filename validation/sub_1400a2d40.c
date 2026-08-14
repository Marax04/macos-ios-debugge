__int64 sub_1400F1D90();
__int64 sub_1400F3360();
__int64 sub_14002EDF0();
__int64 sub_1400A3FB0();
__int64 sub_1400F3326();
__int64 sub_1400A2ED3();
__int64 off_140108030();
extern __int64 off_140108038;

__int64 __fastcall sub_1400A2D40(int *a1, int *a2) {
    int v_20;
    char *str;
    __int64 v5;
    __int64 result;
    __int64 v3;
    __int64 *src;
    __int64 v7;
    __int64 v10;
    __int64 v11;
    __int64 v2;
    int v12;
    __int64 *src2;
    __int64 i;
    __int64 v6;

    sub_1400F1D90(0x1030);
    v5 = (__int64)a2;
    v5 >>= 1;
    result = (__int64)a2;
    result -= v5;
    v5 = 0x7A120;
    if (a2 < 0x7A120) v5 = a2;
    if (v5 <= result) v5 = result;
    v3 = 48;
    if (v5 >= 49) v3 = v5;
    if (v5 >= 257) {
        src = (__int64 *)v3;
        src = (__int64 *)((__int64)(__int64)src << 4);
        result >>= 60;
        result = (result == 0) ? 1 : 0;
        v7 = 0x7FFFFFFFFFFFFFFD;
        v5 = (src < v7) ? 1 : 0;
        if ((result & v5) == 0) {
            sub_1400F3360(a1, a2, v7);
        }
        v10 = (__int64)a1;
        v11 = (__int64)a2;
        sub_14002EDF0(0, src);
        if (result != 0) {
            v_20 = (v11 < 65) ? 1 : 0;
            sub_1400A3FB0(v10, v11, result, v3);
            off_140108030();
            a1 = (int *)result;
            a2 = 0;
            JUMPOUT(off_140108038);
        }
        sub_1400F3326(4, src, result);
        v2 = v6;
        v12 = v5;
        src = (__int64 *)a2;
        v3 = (__int64)a1;
        src2 = *a2;
        if (src2 == 0) JUMPOUT(0x1400a2f0e);
        result = *(src + 8);
        a1 = src2 + 8;
        v11 = *(src2 + 186);
        a2 =  + v11*4;
        i = -1;
        do {
            if (a2 == 0) JUMPOUT(0x1400a2ed0);
            v5 = (v12 > *(a1 + i*4 + 4)) ? 1 : 0;
            v5 -= 0;
            ++i;
            a2 -= 4;
        } while (v5 == 1);
        a2 = (int *)v5;
        if (v5 == 0) JUMPOUT(0x1400a2ee7);
        return sub_1400A2ED3();
    } else {
        v_20 = (a2 < 65) ? 1 : 0;
        sub_1400A3FB0(a1, a2, str, 256);
        return result;
    }
}