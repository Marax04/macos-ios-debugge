// inferred from 3 accesses on `a2`
struct Struct_1_t {
    char _pad_start[24];
    __int64 field_18; // offset 24
    __int64 field_20; // offset 32
    __int64 field_28; // offset 40
};

__int64 sub_1400F3600();
__int64 sub_1400F5F40();
__int64 off_140108030();
__int64 off_140108038();
extern __int64 off_140108278;
extern __int64 off_1401083B0;
extern __int64 off_14012D020;
extern __int64 off_140111F70;
extern __int64 off_14012D018;

__int64 __fastcall sub_1400F28A6(__int64 *a1,struct Struct_1_t *a2) {
    __int64 rsp;
    int arg_10;
    int arg_18;
    int v_20;
    __int64 v_30;
    __int64 *result;
    __m128i xmm0;
    __int64 v4;
    __int64 v2;
    __int64 v3;
    __int64 v8;
    __int64 v5;
    __int64 v9;
    __int64 v6;
    __int64 v7;

    if (!((0 /* unresolved: flags <= */))) {
        *result = *result + (__int64)result;
        JUMPOUT(off_140108278);
        JUMPOUT(result);
        JUMPOUT(off_1401083B0);
        if (arg_18 == 0) {
            result = (__int64 *)arg_10;
            v_30 = (__int64)result;
            xmm0 = _mm_loadu_si128((__m128i *)a1);
            _mm_store_si128((__m128i *)&v_20, xmm0);
            v4 = a2->field_28;
            v2 = a2->field_20;
            if (v4 > v2) JUMPOUT(0x1400f29b8);
            v3 = (__int64)a1;
            v8 = a2->field_18;
            v5 = v8 + v4;
            result = off_14012D020;
            ((__int64 (*)())result)(10, v8, v5);
            if (((__int64)result & 1) != 0) {
                a2 -= v8;
                v9 = a2 + 1;
                if (a2 >= v2) {
                    v6 = &off_140111F70;
                    sub_1400F3600(0, v9, v2, v6);
                    v9 = 0;
                }
                v7 = v8 + v9;
                result = off_14012D018;
                ((__int64 (*)())result)(10, v8, v7);
                a2 = result + 1;
                v4 -= v9;
                a1 = rsp + 32;
                sub_1400F5F40(a1, a2, v4);
                v4 = (__int64)result;
                off_140108030();
                off_140108038(result, 0, v3);
                a1 = result;
                result = a1;
                return (__int64)result;
            }
            return (__int64)result;
        }
    }
    return (__int64)result;
}