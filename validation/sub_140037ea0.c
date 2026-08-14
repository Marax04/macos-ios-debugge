__int64 sub_1400F1D90();
__int64 sub_1400F2808();
__int64 sub_140037FEF();
__int64 sub_1400380CB();
__int64 off_1401081B8();
__int64 off_140108060();
extern __int64 off_140038230;
extern __int64 off_1401081A8;
extern __int64 off_1401081B0;

__int64 __fastcall sub_140037EA0(int a1, int a2) {
    int arg_1000;
    int arg_1004;
    int arg_1008;
    int arg_1010;
    int arg_fb0;
    int arg_fc0;
    int arg_fc8;
    int arg_fd8;
    int arg_fe0;
    int arg_ffc;
    int v_20;
    char *str;
    __int64 v4;
    __m128i xmm6;
    __int64 v6;
    __int64 v7;
    __int64 v9;
    __int64 v3;
    __int64 v5;
    __int64 v2;
    __int64 v8;
    __int64 v1;

    sub_1400F1D90(0x10A8);
    _mm_store_si128((__m128i *)&arg_1010, xmm6);
    arg_1008 = -2;
    arg_fd8 = a2;
    arg_fe0 = a1;
    v4 = str - 80;
    sub_1400F2808(v4, 0, 0x1000);
    xmm6 = _mm_setzero_si128();
    v6 = str + 0xFFC;
    v7 = &off_140038230;
    v9 = off_1401081A8;
    v3 = off_1401081B0;
    arg_ffc = 0;
    _mm_store_si128((__m128i *)&arg_fb0, xmm6);
    arg_fc0 = 0;
    arg_fc8 = v6;
    v_20 = v7;
    v5 = arg_fe0;
    a2 = str - 80;
    off_1401081B8(v5, a2, 0x1000);
    if (v1 == 0) {
        off_140108060(v5);
        v2 = v1;
        v2 <<= 32;
        v2 |= 2;
        v8 = v2;
    } else {
        do {
            ((__int64 (*)())v3)(0xFFFFFFFF, 1);
        } while (arg_ffc != 1);
        v1 = arg_1000;
        v2 = arg_1004;
        v8 = v1;
        v8 <<= 32;
        v8 |= 2;
        if (v1 != 0) v2 = v8;
        if (v1 == 0) {
            return sub_140037FEF();
        }
    }
    v1 = a1;
    v1 &= 3;
    v8 >>= 32;
    if (v1 == 2) JUMPOUT(0x140037fe0);
    v1 = 0;
    if (v8 == 11) v2 = v1;
    if (a1 == 11) JUMPOUT(0x140037fef);
    return sub_1400380CB();
}