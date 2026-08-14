__int64 sub_1400F27F6();
__int64 sub_140075382();

__int64 __fastcall sub_140075914() {
    int v_a8;
    __int64 i;
    __int64 *i2;
    __int64 v10;
    __int64 *v9;
    __int64 *dst3;
    __int64 v12;
    __int64 v11;
    __int64 *dst;
    __int64 *dst2;
    __int64 v14;
    __int64 v5;
    __int64 v6;
    __int64 v13;

    *dst = *dst + (__int64)dst;
    sub_1400F27F6();
    i = dst2 + v14;
    i += 104;
    i2 = dst2 + v5*8;
    i2 += 120;
    sub_1400F27F6(i2, i, v_a8);
    i2 = v11 + 1;
    *(dst2 + v5*8 + 8) = v6;
    v10 = v11 + 2;
    *(dst2 + v5*8 + 112) = v13;
    *(dst2 + 98) = i2;
    if (v12 >= dst) JUMPOUT(0x140075382);
    i2 = (__int64 *)v11;
    i2 -= v5;
    ++i2;
    i2 = (__int64 *)((__int64)(__int64)i2 & 3);
    if (!((i2 == 0))) {
        v9 = dst2 + v5*8;
        v9 += 112;
        for (i = 0; i2 != i; ++i) {
            dst3 = v9[i];
            *dst3 = dst2;
            v9 = v12 + i;
            *(dst3 + 96) = v9;
        }
        v12 += i;
    }
    v11 -= v5;
    if (v11 < 3) JUMPOUT(0x140075382);
    for (; v12 != v10; v12 += 4) {
        i2 = *(dst2 + v12*8 + 104);
        *i2 = dst2;
        *(i2 + 96) = v12;
        i2 = *(dst2 + v12*8 + 112);
        *i2 = dst2;
        i = v12 + 1;
        *(i2 + 96) = i;
        i2 = *(dst2 + v12*8 + 120);
        *i2 = dst2;
        i = v12 + 2;
        *(i2 + 96) = i;
        i2 = *(dst2 + v12*8 + 128);
        *i2 = dst2;
        i = v12 + 3;
        *(i2 + 96) = i;
    }
    return sub_140075382();
}