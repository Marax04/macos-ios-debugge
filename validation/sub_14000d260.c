// inferred from 3 accesses on `ptr`
struct Struct_1_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
};

// inferred from 2 accesses on `ptr2`
struct Struct_2_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
};

__int64 sub_1400F3B20();
__int64 sub_14000A9E0();
__int64 sub_14000D343();
__int64 off_140108030();
__int64 off_140108038();
extern __int64 off_14010AF56;
extern __int64 off_14010AF70;
extern __int64 off_1401084F0;

__int64 __fastcall sub_14000D260(__int64 *a1) {
    struct Struct_2_t *ptr2;
    __int64 *v11;
    __int64 v8;
    __int64 v9;
    __int64 v5;
    __int64 *src;
    __m128i xmm0;
    __int64 result;
    __int64 *src2;
    __int64 *src3;
    struct Struct_1_t *ptr;
    __int64 v7;

    ptr2 = a1[10];
    if (ptr2->field_8 != 3) {
        ptr2 += 8;
        return (__int64)ptr2;
    } else {
        v11 = ptr2->field_0;
        v8 = (__int64)ptr2;
        ((__int64 (*)())(*(v11 + 48)))();
        if (ptr2 == 0) {
            v9 = &off_14010AF56;
            v5 = &off_14010AF70;
            sub_1400F3B20(v9, 24, v5);
            src = (__int64 *)v9;
            xmm0 = _mm_loadu_si128((__m128i *)v11);
            xmm0 = _mm_cmpeq_epi8(xmm0, _mm_load_si128((__m128i *)&off_1401084F0));
            result = _mm_movemask_epi8(xmm0);
            v9 += 8;
            if (result != 0xFFFF) JUMPOUT(0x14000d33e);
            sub_14000A9E0(v9);
            src2 = *(src + 72);
            result = (__int64)src2;
            result &= 3;
            if (result != 1) JUMPOUT(0x14000d343);
            src3 = *(src2 - 1);
            ptr = *(src2 + 7);
            v7 = ptr->field_0;
            if (v7 != 0) {
                ((__int64 (*)())v7)(src3);
            }
            --src2;
            if (ptr->field_8 != 0) {
                if (ptr->field_10 >= 17) {
                    src3 = *(src3 - 8);
                }
                off_140108030();
                off_140108038(v7, 0, src3);
            }
            off_140108030();
            off_140108038(v7, 0, src2);
            return sub_14000D343();
        } else {
            return result;
        }
    }
}