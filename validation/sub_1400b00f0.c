// inferred from 2 accesses on `a2`
struct Struct_1_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
};

// inferred from 3 accesses on `result`
struct Struct_2_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
};

__int64 off_140108030();
__int64 off_140108038();

__int64 __fastcall sub_1400B00F0(__int64 *a1,struct Struct_1_t *a2) {
    __int64 v_28;
    int v_30;
    char *str;
    __int64 v2;
    __int64 *src;
    __int64 *src2;
    struct Struct_2_t *result;
    __int64 v10;
    __int64 v3;
    int v9;
    int v13;
    __int64 v5;
    __int64 *src3;
    __int64 i;
    __int64 v8;
    __int64 v4;

    v2 = a1[2];
    if (v2 != 0) {
        src = *(a1 + 8);
        src2 = a2->field_0;
        result = a2->field_8;
        v_28 = (__int64)result;
        result = *src2;
        v10 = ((__int64 *)a2)[2];
        v3 = 0;
        v9 = 0x2600;
        v13 = 0;
        v_30 = (int)a1;
        a2 =  + (__int64)(__int64)str*4;
        a2 = (struct Struct_1_t *)((__int64)a2 + (__int64)str);
        v5 = *(src + (__int64)(__int64)a2*8 + 24);
        src3 = *(src + (__int64)(__int64)a2*8 + 32);
        src3 = (__int64 *)((__int64)src3 - (__int64)result);
        i = v5;
        i += (__int64)src3;
        while (!((i < 0))) {
            if (i <= v10) {
                if (v5 == 0) {
                    v2 -= v3;
                    result = (struct Struct_2_t *)v_30;
                    result->field_10 = v2;
                    return (__int64)result;
                }
                src3 += v_28;
                for (i = 0; v5 != i; ++i) {
                    v8 = *(src3 + i);
                    v4 = v8 - 32;
                }
                return i;
            }
        }
        result = src + (__int64)(__int64)a2*8;
        if (result->field_0 != 0) {
            v4 = result->field_8;
            off_140108030(a1, a2, v5, src3);
            off_140108038(result, 0, v4);
        }
        v3 = 1;
        if (str != v2) JUMPOUT(0x1400b01ef);
        return v3;
    }
    return (__int64)result;
}