// inferred from 3 accesses on `ptr`
struct Struct_1_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
};

// inferred from 2 accesses on `ptr2`
struct Struct_2_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
};

__int64 sub_140011970();
__int64 sub_140053F72();
__int64 sub_140053F79();
extern __int64 off_140119AA8;
extern __int64 off_14010B3F0;
extern __int64 off_140117680;
extern __int64 off_14010B327;
extern __int64 off_140116230;

__int64 __fastcall sub_140053B90(size_t *a1, size_t *a2) {
    __int64 rsp;
    int arg_18;
    int v_20;
    int v_28;
    __int16 *v_1;
    struct Struct_1_t *ptr;
    struct Struct_2_t *ptr2;
    __int64 result;
    __int64 *src;
    __int64 v12;
    __int64 v5;
    __int64 v2;
    __int64 v7;
    __int64 *src2;
    int v13;
    __int64 v11;
    __m128i xmm0;
    __int64 v9;
    __int64 v10;

    ptr = (struct Struct_1_t *)a2;
    ptr2 = *a1;
    result = a2[2];
    if ((result & 0x2000000) != 0) {
        a1 = ptr2->field_0;
        a2 = 17;
        result = &off_140119AA8;
        src = (__int64 *)a1;
        do {
            v12 = (__int64)a2;
            a2 = a1;
            a2 = (size_t *)((__int64)(__int64)a2 & 15);
            src = (__int64 *)((__int64)(__int64)src >> 4);
            a2 = *(a2 + result);
            *(__int64 *)(rsp + v12 + 58) = a2;
            a2 = v12 - 1;
            a1 = (size_t *)src;
        } while ((a1 > 15));
    } else {
        if ((result & 0x4000000) != 0) {
            a1 = ptr2->field_0;
            a2 = 17;
            result = &off_14010B3F0;
            src = (__int64 *)a1;
            do {
                v12 = (__int64)a2;
                a2 = a1;
                a2 = (size_t *)((__int64)(__int64)a2 & 15);
                src = (__int64 *)((__int64)(__int64)src >> 4);
                a2 = *(a2 + result);
                *(__int64 *)(rsp + v12 + 58) = a2;
                a2 = v12 - 1;
                a1 = (size_t *)src;
            } while ((a1 > 15));
            v12 -= 2;
            result = rsp + v12;
            result += 60;
            a1 = 17;
            a1 = (size_t *)((__int64)a1 - (__int64)a2);
            v_28 = (int)a1;
            v_20 = result;
            v5 = &off_140117680;
            v2 = 1;
            sub_140011970(ptr, 1, v5, 2);
            if (result != 0) JUMPOUT(0x140053f79);
        } else {
            src = ptr2->field_0;
            v5 = 20;
            a2 = (size_t *)src;
            if (src >= 1000) {
                v2 = 20;
                v7 = 0x346DC5D63886594B;
                src2 = &off_14010B327;
                a1 = (size_t *)src;
                do {
                    v5 = v2 - 4;
                    result = (__int64)a1;
                    result *= v7; /* unsigned; high half in a2 */;
                    a2 = (size_t *)((__int64)(__int64)a2 >> 11);
                    result = (__int64)(__int64)a2 * 0x2710;
                    v13 = (int)a1;
                    v13 -= result;
                    result = v13 * 0x147B;
                    result >>= 19;
                    v11 = result * 100;
                    v13 -= v11;
                    result = *(src2 + result*2);
                    xmm0 = _mm_cvtsi32_si128(result);
                    /* pinsrw $1, (%(__int64)src2,%v11,2), %xmm0 */;
                    *(__int64 *)(rsp + v2 + 56) = _mm_cvtsi128_si64(xmm0);
                    v2 = v5;
                    a1 = a2;
                } while ((a1 > 0x98967F));
            }
            if (a2 > 9) {
                result = (__int64)a2;
                result >>= 2;
                result *= 0x147B;
                result >>= 17;
                a1 = result * 100;
                a2 = (size_t *)((__int64)a2 - (__int64)a1);
                a1 = a2;
                a2 = &off_14010B327;
                a1 = *(a2 + (__int64)(__int64)a1*2);
                *(__int64 *)(rsp + v5 + 58) = a1;
                v5 -= 2;
                a2 = (size_t *)result;
            }
            if (src != 0) {
                if (a2 != 0) {
                    a2 = (size_t *)((__int64)(__int64)a2 & 15);
                    result = &off_14010B327;
                    result = v_1[(__int64)a2];
                    *(__int64 *)(rsp + v5 + 59) = result;
                    --v5;
                }
                result = 20;
                result -= v5;
                a1 = rsp + v5;
                a1 += 60;
                v_28 = result;
                v_20 = (int)a1;
                v2 = 1;
                sub_140011970(ptr, 1, 1, 0);
                if (result == 0) {
                    a1 = ptr->field_0;
                    result = ptr->field_8;
                    a2 = &off_140116230;
                    v5 = 2;
                    ((__int64 (*)())(arg_18))();
                    v2 = 1;
                    if (result != 0) JUMPOUT(0x140053f79);
                    result = ptr->field_10;
                    if ((result & 0x2000000) != 0) JUMPOUT(0x140053ec7);
                    if ((result & 0x4000000) != 0) JUMPOUT(0x140053f04);
                    v9 = ptr2->field_8;
                    v5 = 20;
                    src = &off_14010B327;
                    a2 = (size_t *)v9;
                    if (v9 >= 1000) {
                        ptr2 = 20;
                        v10 = 0x346DC5D63886594B;
                        a1 = (size_t *)v9;
                        do {
                            v5 = ptr2 - 4;
                            result = (__int64)a1;
                            result *= v10; /* unsigned; high half in a2 */;
                            a2 = (size_t *)((__int64)(__int64)a2 >> 11);
                            result = (__int64)(__int64)a2 * 0x2710;
                            v2 = (__int64)a1;
                            v2 -= result;
                            result = v2 * 0x147B;
                            result >>= 19;
                            v13 = result * 100;
                            v2 -= v13;
                            result = *(src + result*2);
                            xmm0 = _mm_cvtsi32_si128(result);
                            /* pinsrw $1, (%(__int64)src,%v2,2), %xmm0 */;
                            *(__int64 *)(rsp + ptr2 + 56) = _mm_cvtsi128_si64(xmm0);
                            ptr2 = (struct Struct_2_t *)v5;
                            a1 = a2;
                        } while ((a1 > 0x98967F));
                    }
                    if (a2 > 9) {
                        result = (__int64)a2;
                        result >>= 2;
                        result *= 0x147B;
                        result >>= 17;
                        a1 = result * 100;
                        a2 = (size_t *)((__int64)a2 - (__int64)a1);
                        a1 = a2;
                        a1 = *(src + (__int64)(__int64)a1*2);
                        *(__int64 *)(rsp + v5 + 58) = a1;
                        v5 -= 2;
                        a2 = (size_t *)result;
                    }
                    if (v9 != 0) {
                        if (a2 != 0) {
                            a2 = (size_t *)((__int64)(__int64)a2 & 15);
                            result = *(src + (__int64)(__int64)a2*2 + 1);
                            *(__int64 *)(rsp + v5 + 59) = result;
                            --v5;
                        }
                        result = 20;
                        result -= v5;
                        a1 = rsp + v5;
                        a1 += 60;
                        v_28 = result;
                        v_20 = (int)a1;
                        v5 = 1;
                        a1 = (size_t *)ptr;
                        a2 = 1;
                        src = 0;
                        return sub_140053F72();
                    }
                    return (__int64)src;
                } else {
                    return sub_140053F79();
                }
            }
            return (__int64)src;
        }
        return (__int64)src;
    }
    return result;
}