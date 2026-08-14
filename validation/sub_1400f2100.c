// inferred from 4 accesses on `ptr`
struct Struct_1_t {
    int field_0; // offset 0
    char _pad_0[2];
    __int64 field_6; // offset 6
    char _pad_6[6];
    int field_14; // offset 20
    __int64 field_18; // offset 24
};

// inferred from 2 accesses on `ptr2`
struct Struct_2_t {
    char _pad_start[8];
    int field_8; // offset 8
    __int64 field_C; // offset 12
};

__int64 sub_1400F23EC();
__int64 sub_1400F27D8();
__int64 sub_1400F2892();
extern __int64 off_14012D289;
extern __int64 off_140000000;
extern __int64 off_14000003C;
extern __int64 off_140124DD0;
extern __int64 off_14012D290;
extern __int64 off_14012D2A0;
extern __int64 off_14012D2A8;
extern __int64 off_14012D2B8;

__int64 __fastcall sub_1400F2100(size_t a1) {
    __int64 rsp;
    __int64 v2;
    __int64 v6;
    __int64 result;
    struct Struct_1_t *ptr;
    struct Struct_2_t *ptr2;
    int v3;
    __int64 v8;
    __int64 v7;
    __m128i xmm0;
    __int64 v4;

    v2 = a1;
    if (off_14012D289 == 0) {
        if (a1 > 1) {
            sub_1400F23EC(5);
            v6 = a1;
            result = 0x5A4D;
            if (off_140000000 != result) JUMPOUT(0x1400f2219);
            ptr = off_14000003C;
            ptr2 = &off_140000000;
            ptr = (struct Struct_1_t *)((__int64)ptr + (__int64)ptr2);
            if (ptr->field_0 != 0x4550) JUMPOUT(0x1400f2219);
            result = 523;
            if (ptr->field_18 != result) JUMPOUT(0x1400f2219);
            v6 -= (__int64)ptr2;
            v3 = ptr->field_14;
            ptr2 += 24;
            ptr2 = (struct Struct_2_t *)((__int64)ptr2 + (__int64)ptr);
            result = ptr->field_6;
            v8 = result + result*4;
            v7 = ptr2 + v8*8;
            do {
                *(__int64 *)rsp = ptr2;
                if (ptr2 == v7) JUMPOUT(0x1400f2200);
                a1 = ptr2->field_C;
                if (v6 < v8) {
                    ptr2 += 40;
                }
                result = ptr2->field_8;
                result += a1;
                if (v6 < result) JUMPOUT(0x1400f2202);
                return result;
            } while (true);
        } else {
            sub_1400F27D8();
            if (result != 0) {
                if (v2 != 0) {
                    xmm0 = _mm_load_si128((__m128i *)&off_140124DD0);
                    result |= -1;
                    _mm_storeu_si128((__m128i *)&off_14012D290, xmm0);
                    off_14012D2A0 = result;
                    _mm_storeu_si128((__m128i *)&off_14012D2A8, xmm0);
                    off_14012D2B8 = result;
                } else {
                    v2 = &off_14012D290;
                    sub_1400F2892(v2);
                    if (result == 0) {
                        v4 = &off_14012D2A8;
                        sub_1400F2892(v4);
                        if (result == 0) {
                            off_14012D289 = 1;
                            result = 1;
                        } else {
                            result = 0;
                        }
                        return result;
                    }
                    return result;
                }
                return result;
            }
            return result;
        }
    }
    return result;
}