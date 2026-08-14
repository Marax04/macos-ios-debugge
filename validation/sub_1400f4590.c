__int64 sub_1400F37D0();
__int64 sub_1400F3326();
__int64 sub_1400F5820();
__int64 sub_1400F4692();
extern __int64 off_14011B42B;
extern __int64 off_140110248;

__int64 __fastcall sub_1400F4590(int *a1, int *a2, __int64 a3, __int64 a4) {
    __int64 rsp;
    int v_20;
    int v_28;
    int v_30;
    int v_38;
    int v_40;
    int v_48;
    int v_50;
    __int64 v8;
    __int64 *dst;
    __int64 v4;
    __int64 v3;
    __int64 v1;
    __int64 v5;
    __int64 v6;
    __int64 v7;

    v8 = rsp + 32;
    a1 = &off_14011B42B;
    a3 = &off_140110248;
    sub_1400F37D0(a1, 40, a3);
    a2 += a3;
    if ((a2 < 0)) {
        sub_1400F3326(0);
    } else {
        dst = (__int64 *)a1;
        v4 = *a1;
        a1 = v4 + v4;
        if (a2 > a1) a1 = a2;
        v3 = 4;
        if (a1 >= 5) v3 = a1;
        v1 = *(dst + 8);
        v_20 = a4;
        a1 = rsp + 48;
        sub_1400F5820(a1, v4, v1);
        if (v_30 != 1) {
            v5 = v_38;
            *(dst + 8) = v5;
            *dst = v3;
            return v5;
        }
    }
    a1 = (int *)v_38;
    a2 = (int *)v_40;
    sub_1400F3326(a1, a2);
    v6 = *a2;
    if (v6 == 3) JUMPOUT(0x1400f5035);
    v3 = (__int64)a2;
    v8 = (__int64)a1;
    v7 = a1 + 312;
    v_50 = (int)a2;
    v_48 = v7;
    v_28 = (int)a1;
    return sub_1400F4692();
}