// inferred from 2 accesses on `ptr`
struct Struct_1_t {
    char _pad_start[8];
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
};

__int64 sub_1400F6940();
__int64 sub_1400F3326();
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

__int64 __fastcall sub_1400F71A0(__int64 *a1) {
    __int64 rsp;
    int arg_60;
    int arg_68;
    int arg_8;
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
    __int64 v14;
    struct Struct_1_t *ptr;
    __int64 v3;
    __int64 *result;
    __int64 v5;
    __int64 *dst;
    __m128i xmm0;
    __int64 v12;
    __int64 v13;
    __int64 i;
    __int64 v10;
    __int64 i2;
    __int64 v11;
    __int64 v9;
    __int64 v7;

    v14 = rsp + 80;
    ptr = (struct Struct_1_t *)a1;
    v3 = *a1;
    result = v3 + v3;
    v5 = 4;
    if (result >= 5) v5 = result;
    dst = (__int64 *)arg_8;
    v_28 = 40;
    v_20 = 8;
    a1 = v14 - 24;
    sub_1400F6940(a1, v3, dst, v5);
    if (v_18 == 1) {
        a1 = (__int64 *)v_10;
        v3 = v_8;
        sub_1400F3326(a1, v3);
        v14 = rsp + 112;
        result = v14 - 1;
        v_18 = (__int64)result;
        result = &off_140033360;
        v_10 = (__int64)result;
        result = &off_140113D00;
        v_48 = (__int64)result;
        v_40 = 1;
        v_28 = 0;
        result = v14 - 24;
        v_38 = (__int64)result;
        v_30 = 1;
        v3 = &off_140113CA0;
        a1 = v14 - 72;
        sub_1400F37A0(a1, v3);
        v14 = rsp + 80;
        result = &off_140113BD0;
        v_30 = (__int64)result;
        v_28 = 1;
        v_20 = 8;
        xmm0 = _mm_setzero_si128();
        _mm_storeu_si128((__m128i *)&v_18, xmm0);
        v3 = &off_140113C08;
        a1 = v14 - 48;
        sub_1400F37A0(a1, v3);
        v14 = rsp + 80;
        sub_140038B80();
        result = &off_140113D40;
        v_30 = (__int64)result;
        v_28 = 1;
        v_20 = 8;
        xmm0 = _mm_setzero_si128();
        _mm_storeu_si128((__m128i *)&v_18, xmm0);
        v3 = &off_140113D78;
        a1 = v14 - 48;
        sub_1400F37A0(a1, v3);
        v14 = rsp + 64;
        result = v14 - 8;
        *result = a1;
        a1 = &off_140111FB8;
        dst = v14 - 16;
        *dst = a1;
        a1 = &off_140113038;
        v_28 = (int)a1;
        v_20 = v3;
        v3 = &off_140114390;
        sub_1400F390E(result, v3, dst, v3);
        v14 = rsp + 96;
        v_8 = -2;
        v5 = v7;
        v12 = (__int64)dst;
        v13 = v3;
        ptr = (struct Struct_1_t *)a1;
        i = arg_68;
        v10 = arg_60;
        v_20 = 0;
        v_18 = 2;
        v_10 = 0;
        a1 = v14 - 32;
        sub_1400F68D0(a1);
        result = (__int64 *)v_18;
        *result = 34;
        v_10 = 1;
        v12 += v13;
        v_38 = v13;
        v_30 = v12;
        v_28 = 0;
        a1 = v14 - 32;
        v3 = v14 - 56;
        sub_14002EA90(a1, v3);
        i2 = v_10;
        if (i2 == v_20) {
            a1 = v14 - 32;
            sub_1400F68D0(a1);
        }
        result = (__int64 *)v_18;
        v_0[i2] = 34;
        ++i2;
        v_10 = i2;
        result = v10 + v10*4;
        v11 = v5 + (__int64)(__int64)result*8;
        v9 = v14 - 32;
        while (v5 != v11) {
            i = v_10;
            if (i != v_20) {
                result = (__int64 *)v_18;
                v_0[i] = 32;
                ++i;
                v_10 = i;
                sub_14003F5F0(v9, v5);
                v5 += 40;
                ptr->field_8 = result;
                *(__int64 *)ptr = (__int64)(result);
                if (v_20 != 0) {
                    ptr = (struct Struct_1_t *)v_18;
                    off_140108030(0x8000000000000000);
                    a1 = result;
                    v3 = 0;
                    dst = (__int64 *)ptr;
                    JUMPOUT(off_140108038);
                    result = (__int64 *)v_10;
                    ptr->field_10 = result;
                    xmm0 = _mm_loadu_si128((__m128i *)&v_20);
                    _mm_storeu_si128((__m128i *)ptr, xmm0);
                }
                return _mm_cvtsi128_si64(xmm0);
            }
            sub_1400F68D0(v9);
            return _mm_cvtsi128_si64(xmm0);
        }
        return _mm_cvtsi128_si64(xmm0);
    } else {
        result = (__int64 *)v_10;
        ptr->field_8 = result;
        *(__int64 *)ptr = (__int64)(v5);
        return (__int64)result;
    }
}