// inferred from 2 accesses on `ptr`
struct Struct_1_t {
    __int64 field_0; // offset 0
    char _pad_0[16];
    __int64 field_18; // offset 24
};

__int64 sub_1400F3360();
__int64 sub_14002EDF0();
__int64 sub_1400F3326();
__int64 sub_140011760();
extern __int64 off_14010AD40;

__int64 __fastcall sub_14000EFE0(int a1, __int64 *a2) {
    int v_18;
    __int64 v_20;
    int v_28;
    int v_8;
    char *str;
    struct Struct_1_t *ptr;
    __int64 *dst;
    __int64 v10;
    __int64 v2;
    __int64 *result;
    __int64 v9;
    __int64 v8;
    __int64 v7;
    __m128i xmm0;
    __int64 v5;
    __int64 *v6;

    v_8 = -2;
    ptr = (struct Struct_1_t *)a2;
    dst = (__int64 *)a1;
    v10 = *(a2 + 8);
    if (v10 == 0) {
        if (ptr->field_18 != 0) {
            v2 = 0;
            result = 0;
            if (v2 > 0) result = v2;
            result = (__int64 *)((__int64)result + (__int64)result);
            v2 = (__int64)result;
            if (v2 < 0) {
                sub_1400F3360(a1, a2, v5, v6);
            }
            if (!((0 /* unresolved: flags == */))) {
                sub_14002EDF0(0, v2);
                if (result == 0) {
                    sub_1400F3326(1, v2);
                    result = 1;
                    v2 = 0;
                }
                v_28 = v2;
                v_20 = (__int64)result;
                v_18 = 0;
                if (v10 != 1) {
                    /* test v10 , v10 */;
                }
                v9 = &off_14010AD40;
                v8 = str - 40;
                sub_140011760(v8, v9, ptr);
                if (result != 0) JUMPOUT(0x14000f129);
                v7 = v_18;
                *(dst + 16) = v7;
                xmm0 = _mm_loadu_si128((__m128i *)&v_28);
                _mm_storeu_si128((__m128i *)dst, xmm0);
                return 0;
            }
        }
    } else {
        result = ptr->field_0;
        a1 = v10;
        a1 &= 3;
        if (v10 >= 4) {
            v5 = v10;
            v5 &= -4;
            v6 = result + 56;
            a2 = 0;
            v2 = 0;
            do {
                v2 += *(v6 - 48);
                v2 += *(v6 - 32);
                v2 += *(v6 - 16);
                v2 += *v6;
                a2 += 4;
                v6 += 64;
            } while (v5 != a2);
        } else {
            a2 = 0;
            v2 = 0;
        }
        if (a1 != 0) {
            a2 = (__int64 *)((__int64)(__int64)a2 << 4);
            a2 = (__int64 *)((__int64)a2 + (__int64)result);
            a2 += 8;
            a1 <<= 4;
            v5 = 0;
            do {
                v2 += *(a2 + v5);
                v5 += 16;
            } while (a1 != v5);
        }
        if (ptr->field_18 != 0) {
            if (v2 <= 15) {
                if (*(result + 8) != 0) {
                    return v5;
                }
                return v5;
            }
            return v5;
        }
        return v5;
    }
    return (__int64)result;
}