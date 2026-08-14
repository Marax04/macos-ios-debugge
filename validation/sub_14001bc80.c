// inferred from 3 accesses on `ptr`
struct Struct_1_t {
    char _pad_start[8];
    __int64 field_8; // offset 8
    char _pad_8[112];
    __int64 field_80; // offset 128
    char _pad_80[376];
    __int64 field_200; // offset 512
};

// inferred from 6 accesses on `ptr2`
struct Struct_2_t {
    char _pad_start[120];
    __int64 field_78; // offset 120
    __int64 field_80; // offset 128
    __int64 field_88; // offset 136
    char _pad_88[2064];
    __int64 field_8A0; // offset 0x8A0
    __int64 field_8A8; // offset 0x8A8
    char _pad_8A8[80];
    __int64 field_900; // offset 0x900
};

__int64 sub_14001B630();
__int64 sub_1400F3A38();
__int64 sub_1400F3600();
__int64 sub_14002EDF0();
__int64 sub_1400F27F0();
extern __int64 off_140108030;
extern __int64 off_140108038;
extern __int64 off_1401100A8;
extern __int64 off_140110120;
extern __int64 off_140110090;
extern __int64 off_140110058;
extern __int64 off_140110048;

__int64 __fastcall sub_14001BC80(__int64 *a1, int a2) {
    __int64 rsp;
    int arg_200;
    int v_20;
    char *str;
    struct Struct_1_t *ptr;
    __int64 v3;
    __int64 result;
    __int64 *src;
    struct Struct_2_t *ptr2;
    __int64 *dst;
    __int64 v7;
    __int64 v8;
    __int64 v5;
    __int64 v6;
    __m128i xmm0;
    __m128i xmm1;

    ptr = *a1;
    a1 = ptr->field_200;
    a1 = (__int64 *)((__int64)(__int64)a1 & -8);
    if (!((a1 == 0))) {
        v3 = *a1;
        result = v3;
        result &= 7;
        v_20 = result;
        while (result == 1) {
            sub_14001B630(a1, 0);
            v3 &= -8;
            a1 = (__int64 *)v3;
            a1 = ptr->field_80;
            src = a1;
            src = (__int64 *)((__int64)(__int64)src & -8);
            a2 = *(src + 0x810);
            ptr2 = (struct Struct_2_t *)a2;
            ptr2 = (struct Struct_2_t *)((__int64)(__int64)ptr2 & -8);
            if (!((ptr2 == 0))) {
                v3 = rsp + 72;
                dst = rsp + 40;
                v7 = off_140108030;
                v8 = off_140108038;
                do {
                    result = (__int64)a1;
                    /* cmpxchg %a2, 128(%(__int64)ptr) */;
                    a1 = ptr->field_80;
                    src = a1;
                    src = (__int64 *)((__int64)(__int64)src & -8);
                    a2 = *(src + 0x810);
                    ptr2 = (struct Struct_2_t *)a2;
                    ptr2 = (struct Struct_2_t *)((__int64)(__int64)ptr2 & -8);
                } while (!((ptr2 == 0)));
            }
            v3 = ptr->field_80;
            v3 &= -8;
            ((__int64 (*)())off_140108030)(dst);
            ((__int64 (*)())off_140108038)(result, 0, v3);
            if (ptr != -1) {
                ptr->field_8 = ptr->field_8 - 1;
                if (!((ptr->field_8 != 0))) {
                    v3 = *(__int64 *)(ptr - 8);
                    ((__int64 (*)())off_140108030)();
                    ((__int64 (*)())off_140108038)(result, 0, v3);
                }
            }
            return v3;
        }
        str = 0;
        a2 = &off_1401100A8;
        v5 = &off_140110120;
        a1 = rsp + 32;
        sub_1400F3A38(a1, a2, str, v5);
        v6 = &off_140110090;
        sub_1400F3600(0, ptr2, 64, v6);
        *a1 = *a1 + 1;
        if ((*a1 <= 0)) JUMPOUT(0x14001bfbc);
        v3 = (__int64)a1;
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
        sub_14002EDF0(0, 0x980);
        if (result == 0) JUMPOUT(0x14001bfbe);
        ptr2 = (struct Struct_2_t *)result;
        ptr2 = (struct Struct_2_t *)((__int64)(__int64)ptr2 & -128);
        dst = ptr2 + 128;
        ptr2->field_78 = result;
        ptr2->field_80 = 0;
        ptr2->field_88 = v3;
        a1 = ptr2 + 144;
        a2 = rsp + 32;
        sub_1400F27F0(a1, a2, 0x800);
        xmm0 = _mm_setzero_si128();
        _mm_store_si128((__m128i *)(ptr2 + 0x890), xmm0);
        ptr2->field_8A0 = 1;
        ptr2->field_8A8 = 0;
        ptr2->field_900 = 0;
        result = arg_200;
        ptr2->field_80 = result;
        /* cmpxchg %(__int64)dst, 512(%v3) */;
        if (!((0 /* unresolved: flags == */))) {
            do {
                *dst = result;
                /* cmpxchg %(__int64)dst, 512(%v3) */;
            } while ((0 /* unresolved: flags != */));
        }
        result = (__int64)dst;
        return result;
    }
    return result;
}