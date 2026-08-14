// inferred from 2 accesses on `ptr`
struct Struct_1_t {
    char _pad_start[8];
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
};

__int64 sub_1400F68D0();
__int64 sub_14002EA90();
__int64 sub_14003F5F0();
__int64 off_140108030();
extern __int64 off_140108038;

__int64 __fastcall sub_1400F7340(__int64 *a1, __int64 a2, int a3, __int64 a4) {
    int arg_60;
    int arg_68;
    int v_10;
    int v_18;
    int v_20;
    int v_28;
    int v_30;
    int v_38;
    int v_8;
    char *str;
    __int64 v4;
    __int64 v9;
    __int64 v10;
    struct Struct_1_t *ptr;
    __int64 i;
    __int64 v7;
    __int64 *result;
    __int64 i2;
    __int64 v8;
    __int64 v6;
    __m128i xmm0;

    v_8 = -2;
    v4 = a4;
    v9 = a3;
    v10 = a2;
    ptr = (struct Struct_1_t *)a1;
    i = arg_68;
    v7 = arg_60;
    v_20 = 0;
    v_18 = 2;
    v_10 = 0;
    a1 = str - 32;
    sub_1400F68D0(a1);
    result = (__int64 *)v_18;
    *result = 34;
    v_10 = 1;
    v9 += v10;
    v_38 = v10;
    v_30 = v9;
    v_28 = 0;
    a1 = str - 32;
    a2 = str - 56;
    sub_14002EA90(a1, a2);
    i2 = v_10;
    if (i2 == v_20) {
        a1 = str - 32;
        sub_1400F68D0(a1);
    }
    result = (__int64 *)v_18;
    *(result + i2*2) = 34;
    ++i2;
    v_10 = i2;
    result = v7 + v7*4;
    v8 = v4 + (__int64)(__int64)result*8;
    v6 = str - 32;
    while (v4 != v8) {
        i = v_10;
        if (i != v_20) {
            result = (__int64 *)v_18;
            *(result + i*2) = 32;
            ++i;
            v_10 = i;
            sub_14003F5F0(v6, v4);
            v4 += 40;
            ptr->field_8 = result;
            *(__int64 *)ptr = (__int64)(result);
            if (v_20 != 0) {
                ptr = (struct Struct_1_t *)v_18;
                off_140108030(0x8000000000000000);
                a1 = result;
                a2 = 0;
                a3 = (int)ptr;
                JUMPOUT(off_140108038);
                result = (__int64 *)v_10;
                ptr->field_10 = result;
                xmm0 = _mm_loadu_si128((__m128i *)&v_20);
                _mm_storeu_si128((__m128i *)ptr, xmm0);
            }
            return _mm_cvtsi128_si64(xmm0);
        }
        sub_1400F68D0(v6);
        return _mm_cvtsi128_si64(xmm0);
    }
    return (__int64)result;
}