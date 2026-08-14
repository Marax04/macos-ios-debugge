// inferred from 3 accesses on `a2`
struct Struct_1_t {
    char _pad_start[24];
    __int64 field_18; // offset 24
    __int64 field_20; // offset 32
    __int64 field_28; // offset 40
};

__int64 sub_1400F3600();
__int64 sub_1400F5F40();
extern __int64 off_140111F88;
extern __int64 off_140108630;
extern __int64 off_14012D020;
extern __int64 off_140111F70;
extern __int64 off_14012D018;

__int64 __fastcall sub_1400F5BF0(__int64 *a1,struct Struct_1_t *a2) {
    int v_70;
    __int64 v3;
    __int64 v2;
    __int64 i;
    __int64 result;
    __int64 *src;
    __int64 i2;
    __m128i xmm0;
    __int64 v4;
    __int64 v11;
    __int64 v5;
    __int64 v12;
    __int64 v9;
    __int64 v10;

    v3 = a1[5];
    v2 = a1[4];
    if (v3 > v2) {
        i = &off_140111F88;
        sub_1400F3600(0, v3, v2, i);
        result = v_70;
        result ^= 1;
        result |= i;
        if (result != 1) JUMPOUT(0x1400f5d04);
        result = a2->field_20;
        i = a2->field_28;
        if (i < result) {
            src = a2->field_18;
            result = -result;
            ++i;
            i2 = *(src + i - 1);
            i2 += 208;
            while (i2 < 10) {
                a2->field_28 = i;
                i2 = result + i;
                ++i2;
                ++i;
            }
        }
        xmm0 = _mm_setzero_si128();
        if (v5 == 0) {
            xmm0 = _mm_cvtsi64_si128((__int64)(off_140108630));
        }
        *(a1 + 8) = _mm_cvtsi128_si64(xmm0);
        result = 0;
        *a1 = result;
        return result;
    } else {
        v4 = (__int64)a2;
        v11 = a1[3];
        v5 = v11 + v3;
        result = off_14012D020;
        ((__int64 (*)())result)(10, v11, v5);
        if ((result & 1) != 0) {
            a2 -= v11;
            v12 = a2 + 1;
            if (a2 >= v2) {
                i = &off_140111F70;
                sub_1400F3600(0, v12, v2, i);
                v12 = 0;
            }
            v9 = v11 + v12;
            result = off_14012D018;
            ((__int64 (*)())result)(10, v11, v9);
            a2 = result + 1;
            v3 -= v12;
            a1 = (__int64 *)v4;
            v10 = v3;
            return sub_1400F5F40();
        }
        return result;
    }
}