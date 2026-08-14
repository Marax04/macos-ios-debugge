// inferred from 4 accesses on `result`
struct Struct_1_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
    char _pad_10[144];
    __int64 field_A8; // offset 168
};

// inferred from 11 accesses on `ptr`
struct Struct_2_t {
    __int64 field_0; // offset 0
    char _pad_0[40];
    __int64 field_30; // offset 48
    __int64 field_38; // offset 56
    char _pad_38[96];
    __int64 field_A0; // offset 160
    char _pad_A0[136];
    __int64 field_130; // offset 304
    char _pad_130[16];
    __int64 field_148; // offset 328
    char _pad_148[16];
    __int64 field_160; // offset 352
    __int64 field_168; // offset 360
    __int64 field_170; // offset 368
    __int64 field_178; // offset 376
    char _pad_178[8];
    __int64 field_188; // offset 392
};

// inferred from 2 accesses on `ptr2`
struct Struct_3_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
};

__int64 sub_140056810();
__int64 sub_140046190();
__int64 sub_140056CD0();
__int64 sub_140057260();
__int64 sub_140058230();
__int64 sub_140053730();
__int64 sub_1400F27F0();
__int64 sub_140053180();
__int64 sub_140055E12();
__int64 off_140108030();
__int64 off_140108038();
extern __int64 off_14011D5D0;
extern __int64 off_14011D5E0;

__int64 __fastcall sub_14005577F(__int64 *a1) {
    __int64 rsp;
    int v_100;
    __int64 v_110;
    int v_118;
    int v_120;
    int v_130;
    int v_140;
    int v_150;
    int v_160;
    int v_170;
    int v_180;
    int v_1c8;
    int v_1d0;
    __int64 v_1d8;
    int v_20;
    int v_30;
    int v_38;
    int v_39;
    int v_3b0;
    int v_40;
    int v_48;
    int v_50;
    int v_58;
    int v_60;
    int v_e0;
    int v_f0;
    char *str;
    __m128i xmm0;
    __int64 v12;
    __int64 v9;
    __int64 v4;
    __int64 v2;
    struct Struct_1_t *result;
    __int64 v3;
    __int64 i;
    __int64 v7;
    __int64 v8;
    __m128i xmm1;
    __int64 v10;
    struct Struct_2_t *ptr;
    struct Struct_3_t *ptr2;
    __m128i xmm6;

    *(__int64 *)result = (__int64)(result->field_0 + result);
    v_39 += (__int64)a1;
    { __int64 __xchg_tmp = result; result = v4; v4 = __xchg_tmp; };
    *(__int64 *)result = (__int64)(result->field_0 + result);
    *(__int64 *)result = (__int64)(result->field_0 + a1);
    *(__int64 *)result = (__int64)(result->field_0 + result);
    v_39 += (__int64)a1;
    { __int64 __xchg_tmp = result; result = ptr2; ptr2 = __xchg_tmp; };
    *(__int64 *)result = (__int64)(result->field_0 + result);
    *(__int64 *)result = (__int64)(result->field_0 + result);
    *(__int64 *)result = (__int64)(result->field_0 + result);
    *(__int64 *)ptr2 = (__int64)(ptr2->field_0 + a1);
    off_14011D5D0 += (__int64)result;
    _mm_storeu_si128((__m128i *)(ptr + 256), xmm0);
    xmm0 = _mm_loadu_si128((__m128i *)&off_14011D5E0);
    _mm_storeu_si128((__m128i *)(ptr + 272), xmm0);
    _mm_storeu_si128((__m128i *)(ptr + 288), xmm6);
    v12 = 0x8000000000000003;
    ptr->field_130 = v12;
    ptr->field_148 = v12;
    ptr->field_160 = 0;
    v9 = ptr->field_168;
    v4 = ptr->field_170;
    v2 = ptr->field_178;
    ptr->field_168 = 0;
    ptr->field_170 = 8;
    ptr->field_178 = 0;
    if (v2 == 0) {
        result = ptr->field_30;
        a1 = ptr->field_38;
        v3 = (__int64)(__int64)a1 * 328;
        v3 += (__int64)result;
        i = 0;
        v7 = (__int64)result;
        do {
            v8 = v7;
            while (v8 != v3) {
                v7 = v8 + 328;
                /* cmp *v8 , 8 */;
                v8 = v7;
                ++i;
            }
            if (i != 0) JUMPOUT(0x140055f79);
            xmm0 = _mm_loadu_si128((__m128i *)ptr);
            xmm1 = _mm_load_si128((__m128i *)&v_e0);
            _mm_store_si128((__m128i *)&v_e0, xmm0);
            _mm_storeu_si128((__m128i *)ptr, xmm1);
            xmm0 = _mm_loadu_si128((__m128i *)(ptr + 16));
            xmm1 = _mm_load_si128((__m128i *)&v_f0);
            _mm_store_si128((__m128i *)&v_f0, xmm0);
            _mm_storeu_si128((__m128i *)(ptr + 16), xmm1);
            xmm0 = _mm_loadu_si128((__m128i *)(ptr + 32));
            xmm1 = _mm_load_si128((__m128i *)&v_100);
            _mm_store_si128((__m128i *)&v_100, xmm0);
            _mm_storeu_si128((__m128i *)(ptr + 32), xmm1);
            xmm0 = _mm_load_si128((__m128i *)&v_110);
            v_110 = (__int64)result;
            v_118 = (int)a1;
            _mm_storeu_si128((__m128i *)(ptr + 48), xmm0);
            xmm0 = _mm_loadu_si128((__m128i *)(ptr + 64));
            xmm1 = _mm_load_si128((__m128i *)&v_120);
            _mm_store_si128((__m128i *)&v_120, xmm0);
            _mm_storeu_si128((__m128i *)(ptr + 64), xmm1);
            xmm0 = _mm_loadu_si128((__m128i *)(ptr + 80));
            xmm1 = _mm_load_si128((__m128i *)&v_130);
            _mm_store_si128((__m128i *)&v_130, xmm0);
            _mm_storeu_si128((__m128i *)(ptr + 80), xmm1);
            xmm0 = _mm_loadu_si128((__m128i *)(ptr + 96));
            xmm1 = _mm_load_si128((__m128i *)&v_140);
            _mm_store_si128((__m128i *)&v_140, xmm0);
            _mm_storeu_si128((__m128i *)(ptr + 96), xmm1);
            xmm0 = _mm_loadu_si128((__m128i *)(ptr + 112));
            xmm1 = _mm_load_si128((__m128i *)&v_150);
            _mm_store_si128((__m128i *)&v_150, xmm0);
            _mm_storeu_si128((__m128i *)(ptr + 112), xmm1);
            xmm0 = _mm_loadu_si128((__m128i *)(ptr + 128));
            xmm1 = _mm_load_si128((__m128i *)&v_160);
            _mm_store_si128((__m128i *)&v_160, xmm0);
            _mm_storeu_si128((__m128i *)(ptr + 128), xmm1);
            xmm0 = _mm_loadu_si128((__m128i *)(ptr + 144));
            xmm1 = _mm_load_si128((__m128i *)&v_170);
            _mm_store_si128((__m128i *)&v_170, xmm0);
            _mm_storeu_si128((__m128i *)(ptr + 144), xmm1);
            result = (struct Struct_1_t *)v_180;
            a1 = ptr->field_A0;
            v_180 = (int)a1;
            ptr->field_A0 = result;
            *(__int64 *)ptr2 = (__int64)(v12);
        } while (true);
    } else {
        v10 = v2 - 1;
        if (ptr->field_188 == 0) {
            v_20 = 0;
            a1 = rsp + 48;
            sub_140056810(a1, ptr, v4, v10);
            result = (struct Struct_1_t *)v_30;
            ptr = (struct Struct_2_t *)v_38;
            if (result != v12) {
                xmm0 = _mm_loadu_si128((__m128i *)&v_40);
                xmm1 = _mm_loadu_si128((__m128i *)&v_50);
                _mm_storeu_si128((__m128i *)(ptr2 + 32), xmm1);
                _mm_storeu_si128((__m128i *)(ptr2 + 16), xmm0);
                *(__int64 *)ptr2 = (__int64)(result);
                ptr2->field_8 = ptr;
                ptr2 = (struct Struct_3_t *)v4;
                do {
                    sub_140046190(ptr2);
                    ptr2 += 144;
                    --v2;
                } while ((v2 != 0));
            } else {
                v3 = v10 + v10*8;
                v3 <<= 4;
                v3 += v4;
                ptr += 40;
                sub_140056CD0(str, v3);
                a1 = rsp + 48;
                sub_140057260(a1, ptr, str);
                v3 = v_30;
                result = (struct Struct_1_t *)v_38;
                a1 = (__int64 *)v3;
                a1 = (__int64 *)(-(__int64)a1);
                a1 = (__int64 *)v_40;
                if ((0 /* unresolved: flags !OF */)) JUMPOUT(0x140055c50);
                v3 = result->field_10;
                if (a1 >= v3) JUMPOUT(0x140055f91);
                result = result->field_8;
                a1 = (__int64 *)((__int64)(__int64)(__int64)a1 * 328);
                if (*(__int64 *)((__int64)result + (__int64)a1) != 10) JUMPOUT(0x140055d8d);
                result = (struct Struct_1_t *)((__int64)result + (__int64)a1);
                if (result->field_A8 == 0) JUMPOUT(0x140055d8d);
                result += 8;
                v3 = rsp + 224;
                sub_140058230(result, v3);
                *(__int64 *)ptr2 = (__int64)(v12);
                ptr2 = (struct Struct_3_t *)v4;
                do {
                    sub_140046190(ptr2);
                    ptr2 += 144;
                    --v2;
                } while ((v2 != 0));
            }
            if (v9 != 0) {
                off_140108030();
                off_140108038(result, 0, v4);
            }
            a1 = rsp + 224;
            sub_140053730(a1);
            xmm6 = _mm_load_si128((__m128i *)&v_3b0);
            return _mm_cvtsi128_si64(xmm6);
        } else {
            v_20 = 0;
            a1 = rsp + 48;
            sub_140056810(a1, ptr, v4, v10);
            result = (struct Struct_1_t *)v_30;
            ptr = (struct Struct_2_t *)v_38;
            if (result == v12) {
                v3 = v10 + v10*8;
                v3 <<= 4;
                v3 += v4;
                ptr += 40;
                sub_140056CD0(str, v3);
                a1 = rsp + 48;
                sub_140057260(a1, ptr, str);
                result = 0;
                if (!__OFSUB(result, v_30)) {
                    a1 = rsp + 448;
                    v3 = rsp + 48;
                    sub_1400F27F0(a1, v3, 160);
                    result = 0;
                    /* cmp result , str */;
                    v_38 = 0;
                    v_50 = 0;
                    v_58 = 8;
                    v_60 = 0;
                    v_30 = 11;
                    if ((0 /* unresolved: flags !OF */)) JUMPOUT(0x140055da3);
                } else {
                    result = (struct Struct_1_t *)v_48;
                    v_1d8 = (__int64)result;
                    xmm0 = _mm_loadu_si128((__m128i *)&v_38);
                    _mm_storeu_si128((__m128i *)&v_1c8, xmm0);
                    v_38 = 0;
                    v_50 = 0;
                    v_58 = 8;
                    v_60 = 0;
                    v_30 = 11;
                }
                result = (struct Struct_1_t *)v_1c8;
                a1 = (__int64 *)v_1d0;
                v3 = result->field_10;
                if (a1 >= v3) JUMPOUT(0x140055f91);
                ptr = (__int64)(__int64)a1 * 328;
                ptr += result->field_8;
                a1 = rsp + 48;
                sub_140053180(a1, v3);
                if (ptr->field_0 != 11) JUMPOUT(0x140055dd2);
                ptr += 8;
                return sub_140055E12();
            }
        }
        return (__int64)ptr;
    }
    return (__int64)result;
}