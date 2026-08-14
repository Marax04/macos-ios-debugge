// inferred from 2 accesses on `ptr`
struct Struct_1_t {
    char _pad_start[8];
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
};

__int64 sub_1400F37A0();
__int64 sub_140038B80();
__int64 sub_1400F390E();
__int64 sub_1400F68D0();
__int64 sub_14002EA90();
__int64 sub_14003F5F0();
__int64 off_140108030();
extern __int64 off_140033360;
extern __int64 off_140113D00;
extern __int64 off_140113CA0;
extern __int64 off_140113BD0;
extern __int64 off_140113C08;
extern __int64 off_140113D40;
extern __int64 off_140113D78;
extern __int64 off_140111FB8;
extern __int64 off_140113038;
extern __int64 off_140114390;
extern __int64 off_140108038;

__int64 __fastcall sub_1400F7210() {
    __int64 rsp;
    int arg_60;
    int arg_68;
    __int64 v_10;
    __int64 v_18;
    int v_20;
    int v_28;
    __int64 v_30;
    __int64 v_38;
    int v_40;
    __int64 v_48;
    int v_8;
    __int16 *v_0;
    __int64 v15;
    __int64 *result;
    __int64 v4;
    __int64 v3;
    __m128i xmm0;
    __int64 *dst;
    __int64 v6;
    __int64 v13;
    __int64 v14;
    struct Struct_1_t *ptr;
    __int64 i;
    __int64 v11;
    __int64 i2;
    __int64 v12;
    __int64 v10;
    __int64 v8;

    v15 = rsp + 112;
    result = v15 - 1;
    v_18 = (__int64)result;
    result = &off_140033360;
    v_10 = (__int64)result;
    result = &off_140113D00;
    v_48 = (__int64)result;
    v_40 = 1;
    v_28 = 0;
    result = v15 - 24;
    v_38 = (__int64)result;
    v_30 = 1;
    v4 = &off_140113CA0;
    v3 = v15 - 72;
    sub_1400F37A0(v3, v4);
    v15 = rsp + 80;
    result = &off_140113BD0;
    v_30 = (__int64)result;
    v_28 = 1;
    v_20 = 8;
    xmm0 = _mm_setzero_si128();
    _mm_storeu_si128((__m128i *)&v_18, xmm0);
    v4 = &off_140113C08;
    v3 = v15 - 48;
    sub_1400F37A0(v3, v4);
    v15 = rsp + 80;
    sub_140038B80();
    result = &off_140113D40;
    v_30 = (__int64)result;
    v_28 = 1;
    v_20 = 8;
    xmm0 = _mm_setzero_si128();
    _mm_storeu_si128((__m128i *)&v_18, xmm0);
    v4 = &off_140113D78;
    v3 = v15 - 48;
    sub_1400F37A0(v3, v4);
    v15 = rsp + 64;
    result = v15 - 8;
    *result = v3;
    v3 = &off_140111FB8;
    dst = v15 - 16;
    *dst = v3;
    v3 = &off_140113038;
    v_28 = v3;
    v_20 = v4;
    v4 = &off_140114390;
    sub_1400F390E(result, v4, dst, v4);
    v15 = rsp + 96;
    v_8 = -2;
    v6 = v8;
    v13 = (__int64)dst;
    v14 = v4;
    ptr = (struct Struct_1_t *)v3;
    i = arg_68;
    v11 = arg_60;
    v_20 = 0;
    v_18 = 2;
    v_10 = 0;
    v3 = v15 - 32;
    sub_1400F68D0(v3);
    result = (__int64 *)v_18;
    *result = 34;
    v_10 = 1;
    v13 += v14;
    v_38 = v14;
    v_30 = v13;
    v_28 = 0;
    v3 = v15 - 32;
    v4 = v15 - 56;
    sub_14002EA90(v3, v4);
    i2 = v_10;
    if (i2 == v_20) {
        v3 = v15 - 32;
        sub_1400F68D0(v3);
    }
    result = (__int64 *)v_18;
    v_0[i2] = 34;
    ++i2;
    v_10 = i2;
    result = v11 + v11*4;
    v12 = v6 + (__int64)(__int64)result*8;
    v10 = v15 - 32;
    while (v6 != v12) {
        i = v_10;
        if (i != v_20) {
            result = (__int64 *)v_18;
            v_0[i] = 32;
            ++i;
            v_10 = i;
            sub_14003F5F0(v10, v6);
            v6 += 40;
            ptr->field_8 = result;
            *(__int64 *)ptr = (__int64)(result);
            if (v_20 != 0) {
                ptr = (struct Struct_1_t *)v_18;
                off_140108030(0x8000000000000000);
                v3 = (__int64)result;
                v4 = 0;
                dst = (__int64 *)ptr;
                JUMPOUT(off_140108038);
                result = (__int64 *)v_10;
                ptr->field_10 = result;
                xmm0 = _mm_loadu_si128((__m128i *)&v_20);
                _mm_storeu_si128((__m128i *)ptr, xmm0);
            }
            return _mm_cvtsi128_si64(xmm0);
        }
        sub_1400F68D0(v10);
        return _mm_cvtsi128_si64(xmm0);
    }
    return (__int64)result;
}