// inferred from 2 accesses on `a2`
struct Struct_1_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
};

// inferred from 3 accesses on `ptr`
struct Struct_2_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
};

__int64 sub_1400138C0();
__int64 sub_140013814();
extern __int64 off_140121048;

__int64 __fastcall sub_140013660(__int64 *a1,struct Struct_1_t *a2) {
    int arg_4;
    int v_10;
    int v_18;
    int v_20;
    int v_28;
    int v_8;
    char *dst;
    __int64 v5;
    struct Struct_2_t *ptr;
    __int64 v7;
    __int64 v8;
    __m128i xmm0;
    __m128i xmm1;
    __int64 v2;
    __int64 v10;
    __int64 v4;
    __int64 *v6;
    __int64 result;
    __int64 v9;
    __int64 *src;

    v5 = (__int64)a2;
    ptr = (struct Struct_2_t *)a1;
    v7 = a1[2];
    if (v7 == 0) {
        v8 = ptr->field_0;
        a2 = ptr->field_8;
        return sub_1400138C0();
    } else {
        xmm0 = _mm_loadu_si128((__m128i *)v5);
        xmm1 = _mm_loadu_si128((__m128i *)(v5 + 16));
        _mm_store_si128((__m128i *)&v_10, xmm1);
        _mm_store_si128((__m128i *)&v_20, xmm0);
        v2 = ptr->field_10;
        if ((v2 & 0x1000000) != 0) {
            v10 = v7;
            a2 = (struct Struct_1_t *)v_20;
            v4 = v_18;
            v10 = ptr->field_0;
            v6 = ptr->field_8;
            v5 = v4;
            ((__int64 (*)())(*(v6 + 24)))();
            if (result != 0) JUMPOUT(0x140013858);
            v_20 = 1;
            v_18 = 0;
            result = 0;
            v7 = v10;
            v7 -= v4;
            if (v7 < 0) v7 = result;
            v4 = v2;
            v4 &= 0x9FE00000;
            v4 |= 0x20000030;
            ptr->field_10 = v4;
            v7 = v_8;
            if (v7 != 0) {
                a2 = (struct Struct_1_t *)v_10;
                v9 = 0;
                do {
                    v5 = a2->field_0;
                    v5 = a2->field_8;
                    v9 += v5;
                    a2 += 24;
                    --v7;
                } while (!((v7 == 0)));
            } else {
                v9 = 0;
            }
            v9 += (__int64)v6;
            result = v7;
            if (v9 >= v6) JUMPOUT(0x1400137f2);
            a2 = (struct Struct_1_t *)v7;
            a2 -= v9;
            result = v4;
            result >>= 29;
            result &= 3;
            src = &off_140121048;
            v6 = *(src + (__int64)(__int64)v6*4);
            v6 = (__int64 *)((__int64)v6 + (__int64)src);
            v_28 = v2;
            *dst = v7;
            arg_4 = (int)a2;
            JUMPOUT(v6);
            return sub_140013814();
        } else {
            v6 = (__int64 *)v_18;
            v4 = v2;
            v7 = v_8;
            if (v7 == 0) {
                return v7;
            } else {
                return v7;
            }
            return v7;
        }
        return result;
    }
}