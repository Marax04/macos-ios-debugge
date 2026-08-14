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

__int64 __fastcall sub_1400F7380() {
    int v_10;
    int v_18;
    int v_20;
    int v_28;
    int v_30;
    int v_38;
    __int64 v3;
    __int64 *result;
    __int64 v11;
    __int64 v4;
    __int64 i;
    __int64 v10;
    __int64 v8;
    __int64 i2;
    __int64 v6;
    struct Struct_1_t *ptr;
    __m128i xmm0;
    __int64 v13;
    __int64 v12;
    __int64 v9;

    *result = *result + (__int64)result;
    *result = *result + (__int64)result;
    v3 = v13 - 32;
    sub_1400F68D0(v3);
    result = (__int64 *)v_18;
    *result = 34;
    v_10 = 1;
    v11 += v12;
    v_38 = v12;
    v_30 = v11;
    v_28 = 0;
    v3 = v13 - 32;
    v4 = v13 - 56;
    sub_14002EA90(v3, v4);
    i = v_10;
    if (i == v_20) {
        v3 = v13 - 32;
        sub_1400F68D0(v3);
    }
    result = (__int64 *)v_18;
    *(result + i*2) = 34;
    ++i;
    v_10 = i;
    result = v9 + v9*4;
    v10 = v6 + (__int64)(__int64)result*8;
    v8 = v13 - 32;
    while (v6 != v10) {
        i2 = v_10;
        if (i2 != v_20) {
            result = (__int64 *)v_18;
            *(result + i2*2) = 32;
            ++i2;
            v_10 = i2;
            sub_14003F5F0(v8, v6);
            v6 += 40;
            ptr->field_8 = result;
            *(__int64 *)ptr = (__int64)(result);
            if (v_20 != 0) {
                ptr = (struct Struct_1_t *)v_18;
                off_140108030(0x8000000000000000);
                v3 = (__int64)result;
                v4 = 0;
                JUMPOUT(off_140108038);
                result = (__int64 *)v_10;
                ptr->field_10 = result;
                xmm0 = _mm_loadu_si128((__m128i *)&v_20);
                _mm_storeu_si128((__m128i *)ptr, xmm0);
            }
            return _mm_cvtsi128_si64(xmm0);
        }
        sub_1400F68D0(v8);
        return _mm_cvtsi128_si64(xmm0);
    }
    return (__int64)result;
}