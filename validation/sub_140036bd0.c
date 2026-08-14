// inferred from 3 accesses on `ptr`
struct Struct_1_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
};

__int64 sub_140031320();
__int64 sub_140036DFD();
__int64 off_140108370();
__int64 off_140108068();
extern __int64 off_140112D18;

__int64 __fastcall sub_140036BD0(int a1, int *a2, int a3, __int64 a4) {
    int arg_10;
    int arg_18;
    int arg_28;
    int arg_38;
    int arg_40;
    int arg_8;
    int v_20;
    int v_28;
    int v_30;
    int v_38;
    char *str;
    struct Struct_1_t *ptr;
    __int64 v8;
    __int64 v2;
    __int64 result;
    __int64 v9;
    __int64 v3;
    __int64 v7;
    __m128i xmm6;
    __int64 v5;
    __int64 v6;
    __m128i xmm0;

    _mm_store_si128((__m128i *)&arg_40, xmm6);
    ptr = (struct Struct_1_t *)a2;
    arg_38 = a1;
    v8 = *a2;
    v2 = a2[2];
    result = v8;
    result -= v2;
    v9 = v8;
    v3 = v2;
    if (result < 32) {
        a1 = arg_38;
        sub_140031320(a1, ptr);
        v3 = (__int64)ptr;
        if ((result & 1) == 0) {
            if (v3 == 0) JUMPOUT(0x140036dda);
            v9 = ptr->field_0;
            v3 = ptr->field_10;
            arg_28 = v2;
            v7 = 0x2000;
            xmm6 = _mm_setzero_si128();
            v2 = 0;
            do {
                arg_8 = a3;
                v5 = ptr->field_8;
                if (v3 == v9) JUMPOUT(0x140036d91);
                v6 = v9;
                v6 -= v3;
                if (v7 < v6) v6 = v7;
                xmm0 = _mm_loadu_si128((__m128i *)&off_140112D18);
                _mm_store_si128((__m128i *)&arg_10, xmm0);
                a1 = 0xFFFFFFFF;
                result = v6;
                if (v6 < a1) {
                    v5 += v3;
                    _mm_storeu_si128((__m128i *)&v_38, xmm6);
                    v_28 = v5;
                    a1 = str + 16;
                    v_20 = a1;
                    v_30 = result;
                    a1 = arg_38;
                    off_140108370(a1, 0, 0, 0);
                    if (result != 259) {
                        if (result == 0xC0000011) JUMPOUT(0x140036df3);
                        if (result == 259) JUMPOUT(0x140036e3f);
                        a3 = arg_8;
                        if (result < 0) JUMPOUT(0x140036dde);
                        a1 = arg_18;
                        result = v2;
                        if (a1 > v2) v2 = a1;
                        v3 += a1;
                        ptr->field_10 = v3;
                        if (a1 == 0) JUMPOUT(0x140036df7);
                        v2 = result;
                        v2 -= a1;
                        ++a3;
                        if (a1 < v6) {
                            a1 = (0 /* unresolved: flags != */) ? 1 : 0;
                            a2 = -1;
                            if (a3 >= 2) {
                                if (result != v6) v7 = a2;
                                result = (v6 < v7) ? 1 : 0;
                                a1 |= result;
                                /* test v7 , v7 */;
                                v7 += v7;
                                v7 = -1;
                            }
                            a2 = (int *)v7;
                            return (__int64)a2;
                        }
                        a3 = 0;
                        return a3;
                    }
                    a1 = arg_38;
                    off_140108068(a1, 0xFFFFFFFF);
                    result = arg_10;
                    return result;
                }
                result = 0xFFFFFFFF;
                return result;
            } while ((v7 >= 0));
        }
        result = 1;
        return sub_140036DFD();
    }
    return result;
}