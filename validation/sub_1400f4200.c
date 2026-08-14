// inferred from 4 accesses on `result`
struct Struct_1_t {
    __int64 field_0; // offset 0
    char _pad_0[376];
    __int64 field_180; // offset 384
    char _pad_180[1664];
    __int64 field_808; // offset 0x808
    __int64 field_810; // offset 0x810
};

// inferred from 2 accesses on `ptr`
struct Struct_2_t {
    char _pad_start[256];
    __int64 field_100; // offset 256
    char _pad_100[120];
    __int64 field_180; // offset 384
};

// inferred from 7 accesses on `ptr2`
struct Struct_3_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
    char _pad_8[2048];
    __int64 field_810; // offset 0x810
    __int64 field_818; // offset 0x818
    __int64 field_820; // offset 0x820
    __int64 field_828; // offset 0x828
    char _pad_828[80];
    __int64 field_880; // offset 0x880
};

__int64 sub_1400F1D90();
__int64 sub_1400F35E0();
__int64 sub_1400F3D20();
__int64 sub_1400F27F0();
__int64 sub_14002EDF0();
__int64 sub_1400F3340();
__int64 sub_14001BC80();
extern __int64 off_1401177B0;
extern __int64 off_140110058;
extern __int64 off_140110048;

__int64 __fastcall sub_1400F4200(int *a1) {
    __int64 rsp;
    int arg_810;
    int arg_818;
    int arg_820;
    __int64 v_820;
    struct Struct_1_t *result;
    struct Struct_3_t *ptr2;
    __int64 v3;
    struct Struct_2_t *ptr;
    __m128i xmm0;
    __m128i xmm1;
    __int64 v5;
    __int64 v7;
    __int64 v6;

    sub_1400F1D90(0x1028);
    arg_820 = 1;
    v_820 = (__int64)a1;
    result = (struct Struct_1_t *)arg_818;
    if (result == -1) {
        a1 = &off_1401177B0;
        sub_1400F35E0(a1);
    } else {
        ptr2 = (struct Struct_3_t *)a1;
        a1 = result + 1;
        ptr2->field_818 = a1;
        if (result == 0) {
            result = ptr2->field_8;
            a1 = result->field_180;
            a1 = (int *)((__int64)(__int64)a1 | 1);
            result = 0;
            /* cmpxchg %(__int64)a1, 0x880(%(__int64)ptr2) */;
            result = ptr2->field_828;
            a1 = result + 1;
            ptr2->field_828 = a1;
            if (((__int64)result & 127) == 0) {
                a1 = ptr2->field_8;
                a1 += 128;
                v3 = rsp + 0x820;
                sub_1400F3D20(a1, v3);
            }
        }
        ptr = ptr2->field_8;
        result = 96;
        xmm0 = _mm_loadu_si128((__m128i *)&off_140110058);
        xmm1 = _mm_loadu_si128((__m128i *)&off_140110048);
        do {
            _mm_storeu_si128((__m128i *)&*(__int64 *)(rsp + result - 48), xmm0);
            _mm_storeu_si128((__m128i *)&*(__int64 *)(rsp + result - 64), xmm1);
            _mm_storeu_si128((__m128i *)&*(__int64 *)(rsp + result - 32), xmm1);
            _mm_storeu_si128((__m128i *)&*(__int64 *)(rsp + result - 16), xmm0);
            _mm_storeu_si128((__m128i *)&*(__int64 *)(rsp + result), xmm1);
            _mm_storeu_si128((__m128i *)&*(__int64 *)(rsp + result + 16), xmm0);
            _mm_storeu_si128((__m128i *)&*(__int64 *)(rsp + result + 32), xmm1);
            _mm_storeu_si128((__m128i *)&*(__int64 *)(rsp + result + 48), xmm0);
            result += 128;
        } while (result != 0x860);
        v5 = ptr2 + 16;
        a1 = rsp + 0x820;
        sub_1400F27F0(a1, v5, 0x808);
        v3 = rsp + 32;
        sub_1400F27F0(v5, v3, 0x800);
        ptr2->field_810 = 0;
        *(__int64 *)rsp = *(__int64 *)rsp | 0;
        v7 = ptr->field_180;
        sub_14002EDF0(0, 0x818);
        if (result == 0) {
            sub_1400F3340(8, 0x818);
        } else {
            v5 = (__int64)result;
            v3 = rsp + 0x820;
            sub_1400F27F0(result, v3, 0x808);
            result->field_808 = v7;
            result->field_810 = 0;
            do {
                a1 = ptr->field_100;
                v3 = (__int64)a1;
                v3 &= -8;
                v6 = arg_810;
                result = (struct Struct_1_t *)a1;
                /* cmpxchg %v6, 256(%(__int64)ptr) */;
            } while ((v3 != 0));
            result = (struct Struct_1_t *)a1;
            /* cmpxchg %v5, 256(%(__int64)ptr) */;
            result = ptr2->field_818;
            a1 = result - 1;
            ptr2->field_818 = a1;
            if (result == 1) {
                ptr2->field_880 = 0;
                if (ptr2->field_820 == 0) {
                    sub_1400F4200(ptr2);
                }
            }
            ptr2->field_820 = 0;
            result = ptr2->field_8;
            *(__int64 *)ptr2 = (__int64)(ptr2->field_0 | 1);
            v_820 = (__int64)result;
            *(__int64 *)result = (__int64)(result->field_0 - 1);
            if (!((result->field_0 != 0))) {
                a1 = rsp + 0x820;
                sub_14001BC80(a1, v3, v6);
            }
            return (__int64)a1;
        }
        return (__int64)a1;
    }
    return (__int64)result;
}