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

__int64 sub_140054C7A();
__int64 sub_140054C98();
__int64 sub_140054C91();

__int64 __fastcall sub_140054AA0(__int64 *a1,struct Struct_1_t *a2,struct Struct_2_t *a3) {
    __int64 v5;
    __int64 v6;
    __int64 *src;
    __int64 *src2;
    __int64 v8;
    __int64 v7;
    __int64 v2;
    __int64 v4;
    __m128i xmm0;
    __int64 result;
    __int64 *src3;
    __int64 v11;

    v5 = ((__int64 *)a2)[2];
    v6 = a2->field_0;
    src = a2->field_8;
    if (v5 == 0) {
        if (v6 == 0) {
            src2 = a3->field_10;
            v8 = a3->field_18;
            if (v8 == 0) {
                a2 = 0;
                return sub_140054C7A();
            } else {
                v6 = ((__int64 *)a2)[3];
                v7 = ((__int64 *)a2)[3];
                a2 = 0;
                do {
                    v2 = *(__int64 *)((__int64)src2 + (__int64)a2);
                    ++a2;
                    if (v8 == a2) JUMPOUT(0x140054c77);
                } while (true);
            }
        }
    } else {
        if (v5 != 1) {
            v2 = -1;
            if (v6 == 0) src = v2;
        } else {
            if (v6 == 0) {
                v4 = a3->field_18;
                if (v4 != 0) {
                    src = a3->field_10;
                    v6 = ((__int64 *)a2)[3];
                    v7 = ((__int64 *)a2)[3];
                    a2 = 0;
                    do {
                        v2 = *(__int64 *)((__int64)src + (__int64)a2);
                        ++a2;
                    } while (v4 != a2);
                    a2 = (struct Struct_1_t *)v4;
                    if (v4 != 0) {
                        v6 = (__int64)src + (__int64)a2;
                        v4 -= (__int64)a2;
                        a3->field_10 = v6;
                        a3->field_18 = v4;
                        a3 = 3;
                    } else {
                        xmm0 = _mm_setzero_si128();
                        _mm_storeu_si128((__m128i *)(a1 + 24), xmm0);
                        a2 = 8;
                        a3 = 1;
                        result = 0;
                    }
                    *a1 = a3;
                    *(a1 + 8) = src;
                    a1[2] = a2;
                    return sub_140054C98();
                }
                return result;
            }
        }
    }
    if (src >= v5) {
        src3 = a3->field_10;
        v7 = a3->field_18;
        if (v7 != 0) {
            v2 = ((__int64 *)a2)[3];
            src3 = ((__int64 *)a2)[3];
            a2 = 0;
            do {
                v4 = *(__int64 *)((__int64)src3 + (__int64)a2);
                if (src != a2) {
                    ++a2;
                    if (v5 > v7) {
                        xmm0 = _mm_setzero_si128();
                        _mm_storeu_si128((__m128i *)(a1 + 24), xmm0);
                        *a1 = 1;
                        *(a1 + 8) = 0;
                        a1[2] = 8;
                        return sub_140054C98();
                    } else {
                        v11 = src3 + v7;
                        a3->field_10 = v11;
                        a3->field_18 = 0;
                        *(a1 + 8) = src3;
                        a1[2] = v7;
                        return sub_140054C91();
                    }
                }
                v7 -= (__int64)src;
                if ((v7 < 0)) JUMPOUT(0x140054cb7);
                a2 = (__int64)src3 + (__int64)src;
                a3->field_10 = a2;
                a3->field_18 = v7;
                *(a1 + 8) = src3;
                a1[2] = src;
                return sub_140054C91();
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