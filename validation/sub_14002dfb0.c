__int64 sub_140028050();
__int64 sub_1400281E0();
__int64 sub_1400F6C10();
extern __int64 off_14012D270;
extern __int64 off_140112C90;
extern __int64 off_140124F80;
extern __int64 off_140108418;

__int64 __fastcall sub_14002DFB0(int *a1, __int64 *a2) {
    __int64 rsp;
    int arg_10;
    int arg_18;
    int arg_8;
    int v_10;
    int v_18;
    int v_30;
    int v_38;
    int v_4;
    int v_40;
    int v_48;
    int v_8;
    __int64 *v_0;
    __int64 *dst;
    __int64 v4;
    __int64 *result;
    __int64 *v5;
    __int64 v9;
    __m128i xmm0;
    __int64 v3;
    __int64 v6;
    __int64 i;
    __int64 *dst2;

    dst = rsp + 112;
    *dst = -2;
    v4 = (__int64)a1;
    result = off_14012D270;
    a1 = __readgsqword(88);
    v5 = v_0[(__int64)v5];
    if (*(v5 + 40) != 0) {
        v_8 = 0;
        v_4 = 0;
        v9 = &off_140112C90;
        v_48 = v9;
        v_40 = 1;
        v_38 = 8;
        xmm0 = _mm_setzero_si128();
        _mm_storeu_si128((__m128i *)&v_30, xmm0);
        a1 = dst - 8;
        a2 = dst - 72;
        sub_140028050(a1, a2);
        v_18 = v9;
        a1 = dst - 24;
        sub_1400281E0(a1);
        a1 = 7;
        /* int $41 */;
        v_10 = (int)a2;
        dst = a2 + 112;
        result = (__int64 *)v_10;
        *result = *result + 1;
        return (__int64)result;
    } else {
        v3 = (__int64)a2;
        a1 = v5 + 40;
        *a1 = -1;
        result = off_140124F80;
        v6 = off_140108418;
        i = a1[3];
        v_10 = (int)a1;
        if (i == arg_8) {
            a1 = v_10 + 8;
            sub_1400F6C10(a1);
        }
        a2 = (__int64 *)v_10;
        dst2 = (__int64 *)arg_10;
        a1 = (int *)i;
        a1 = (int *)((__int64)(__int64)a1 << 4);
        *(__int64 *)((__int64)dst2 + (__int64)a1) = v4;
        *(__int64 *)((__int64)dst2 + (__int64)a1 + 8) = v3;
        ++i;
        arg_18 = i;
        *a2 = *a2 + 1;
        return (__int64)result;
    }
}