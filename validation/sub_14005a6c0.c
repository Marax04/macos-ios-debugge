// inferred from 2 accesses on `a2`
struct Struct_1_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
};

// inferred from 2 accesses on `a3`
struct Struct_2_t {
    char _pad_start[16];
    __int64 field_10; // offset 16
    __int64 field_18; // offset 24
};

__int64 sub_14005A910();
__int64 sub_14005A92E();
__int64 sub_14005A927();

__int64 __fastcall sub_14005A6C0(__int64 *a1,struct Struct_1_t *a2,struct Struct_2_t *a3) {
    __int64 v5;
    __int64 v6;
    __int64 *src;
    __int64 *src2;
    __int64 v8;
    __int64 v7;
    __int64 *src3;
    __int64 v3;
    __int64 v4;
    int v12;
    __m128i xmm0;
    __int64 result;
    __int64 v11;

    v5 = ((__int64 *)a2)[2];
    v6 = a2->field_0;
    src = a2->field_8;
    if (v5 == 0) {
        if (v6 == 0) {
            src2 = a3->field_10;
            v8 = a3->field_18;
            if (v8 == 0) JUMPOUT(0x14005a90e);
            v6 = ((__int64 *)a2)[3];
            v7 = ((__int64 *)a2)[3];
            src3 = ((__int64 *)a2)[3];
            v3 = ((__int64 *)a2)[3];
            v4 = ((__int64 *)a2)[3];
            v12 = ((__int64 *)a2)[4];
            a2 = 0;
            do {
                src2 = *(__int64 *)((__int64)src2 + (__int64)a2);
                if (src3 > src2) {
                    if (v4 > src2) JUMPOUT(0x14005a910);
                    if (src2 <= v12) {
                        ++a2;
                        if (v8 == a2) JUMPOUT(0x14005a909);
                    }
                    return sub_14005A910();
                }
                if (src2 <= v3) {
                    return (__int64)a2;
                }
                return (__int64)a2;
            } while (true);
        }
    } else {
        if (v5 != 1) {
            v6 = -1;
            if (v6 == 0) src = v6;
        } else {
            if (v6 == 0) {
                v4 = a3->field_18;
                if (v4 != 0) {
                    src = a3->field_10;
                    v6 = ((__int64 *)a2)[3];
                    v7 = ((__int64 *)a2)[3];
                    src3 = ((__int64 *)a2)[3];
                    v3 = ((__int64 *)a2)[3];
                    v4 = ((__int64 *)a2)[3];
                    v12 = ((__int64 *)a2)[4];
                    a2 = 0;
                    do {
                        src2 = *(__int64 *)((__int64)src + (__int64)a2);
                        if (src3 > src2) {
                            if (v4 <= src2) {
                                if (src2 <= v12) {
                                    ++a2;
                                    a2 = (struct Struct_1_t *)v4;
                                    if (a2 == 0) {
                                        xmm0 = _mm_setzero_si128();
                                        _mm_storeu_si128((__m128i *)(a1 + 24), xmm0);
                                        a2 = 8;
                                        a3 = 1;
                                        result = 0;
                                    } else {
                                        v3 = (__int64)src + (__int64)a2;
                                        v4 -= (__int64)a2;
                                        a3->field_10 = v3;
                                        a3->field_18 = v4;
                                        a3 = 3;
                                    }
                                    *a1 = a3;
                                    *(a1 + 8) = src;
                                    a1[2] = a2;
                                    return sub_14005A92E();
                                }
                            }
                            return (__int64)a3;
                        }
                        if (src2 <= v3) {
                            return (__int64)a3;
                        }
                        return (__int64)a3;
                    } while (v4 != a2);
                    return (__int64)a3;
                }
                return (__int64)a3;
            }
        }
    }
    if (src >= v5) {
        src3 = a3->field_10;
        v7 = a3->field_18;
        if (v7 != 0) {
            src3 = ((__int64 *)a2)[3];
            v3 = ((__int64 *)a2)[3];
            v4 = ((__int64 *)a2)[3];
            v12 = ((__int64 *)a2)[3];
            src2 = ((__int64 *)a2)[3];
            v11 = ((__int64 *)a2)[4];
            a2 = 0;
            do {
                v8 = *(__int64 *)((__int64)src3 + (__int64)a2);
                if (v4 > v8) {
                    if (src2 > v8) JUMPOUT(0x14005a93d);
                    if (v8 > v11) JUMPOUT(0x14005a93d);
                    if (src != a2) {
                        ++a2;
                        if (v5 <= v7) {
                            v11 = src3 + v7;
                            a3->field_10 = v11;
                            a3->field_18 = 0;
                            *(a1 + 8) = src3;
                            a1[2] = v7;
                            return sub_14005A927();
                        } else {
                            xmm0 = _mm_setzero_si128();
                            _mm_storeu_si128((__m128i *)(a1 + 24), xmm0);
                            *a1 = 1;
                            *(a1 + 8) = 0;
                            a1[2] = 8;
                            return sub_14005A92E();
                        }
                    }
                    v7 -= (__int64)src;
                    if ((v7 < 0)) JUMPOUT(0x14005a95d);
                    a2 = (__int64)src3 + (__int64)src;
                    a3->field_10 = a2;
                    a3->field_18 = v7;
                    *(a1 + 8) = src3;
                    a1[2] = src;
                    return sub_14005A927();
                }
                if (v8 <= v12) {
                    return (__int64)a2;
                }
                return (__int64)a2;
            } while (v7 != a2);
        }
        return (__int64)a2;
    } else {
        xmm0 = _mm_setzero_si128();
        _mm_storeu_si128((__m128i *)(a1 + 24), xmm0);
        *a1 = 2;
    }
    return result;
}