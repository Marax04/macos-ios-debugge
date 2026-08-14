// inferred from 2 accesses on `a1`
struct Struct_1_t {
    char _pad_start[512];
    __int64 field_200; // offset 512
    __int64 field_208; // offset 520
};

// inferred from 2 accesses on `a2`
struct Struct_2_t {
    char _pad_start[40];
    __int64 field_28; // offset 40
    __int64 field_30; // offset 48
};

// inferred from 4 accesses on `ptr`
struct Struct_3_t {
    char _pad_start[16];
    __int64 field_10; // offset 16
    __int64 field_18; // offset 24
    char _pad_18[56];
    __int64 field_58; // offset 88
    __int64 field_60; // offset 96
};

// inferred from 8 accesses on `ptr2`
struct Struct_4_t {
    char _pad_start[8];
    __int64 field_8; // offset 8
    char _pad_8[112];
    __int64 field_80; // offset 128
    __int64 field_88; // offset 136
    char _pad_88[112];
    __int64 field_100; // offset 256
    __int64 field_108; // offset 264
    __int64 field_110; // offset 272
    char _pad_110[32];
    __int64 field_138; // offset 312
    __int64 field_140; // offset 320
};

__int64 sub_14002EDF0();
__int64 sub_1400F3340();
__int64 sub_14001F199();
__int64 off_140108030();
extern __int64 off_14012D188;
extern __int64 off_140108038;

__int64 __fastcall sub_14001EF00(struct Struct_1_t *a1,struct Struct_2_t *a2, __int64 a3, __int64 a4) {
    int v_27;
    int v_28;
    int v_30;
    struct Struct_3_t *ptr;
    struct Struct_4_t *ptr2;
    __int64 v2;
    __int64 v11;
    __int64 v5;
    __int64 v6;
    __int64 v9;
    __int64 v10;
    __int64 v7;
    __int64 v8;
    __m128i xmm0;
    __m128i xmm1;
    __int64 result;

    ptr = (struct Struct_3_t *)a2;
    ptr2 = (struct Struct_4_t *)a1;
    v2 = a2->field_28;
    v11 = a2->field_30;
    sub_14002EDF0(8, 0x5F0);
    if (result != 0) {
        v_27 = v11;
        v_30 = v2;
        a2 = ptr + 56;
        a1 = ptr->field_60;
        v_28 = (int)a1;
        v5 = 0xDED7D4E2D7DEDFC6;
        v6 = 0xA60C596FC19FEAD0;
        v9 = 0xE414A674F0DE7325;
        v10 = 0x800000000000000;
        do {
            v11 = 1;
            /* xadd %v11, off_14012D188 */;
            v7 = v11;
            v7 ^= a3;
            a1 = (struct Struct_1_t *)v7;
            a1 = __ROL8__(a1, 16);
            v2 = v7 + a4;
            a1 = (struct Struct_1_t *)((__int64)(__int64)a1 ^ v2);
            v2 = a1 + v5;
            v11 ^= v2;
            v7 += v6;
            v8 = v7;
            v8 = __ROL8__(v8, 32);
            a1 = __ROL8__(a1, 21);
            v7 ^= v9;
            v2 ^= v10;
            v2 ^= (__int64)a1;
            v11 += v7;
            v7 = __ROL8__(v7, 13);
            v8 += v2;
            v7 ^= v11;
            v2 = __ROL8__(v2, 16);
            v2 ^= v8;
            v11 = __ROL8__(v11, 32);
            v8 += v7;
            v11 += v2;
            v7 = __ROL8__(v7, 17);
            v7 ^= v8;
            v2 = __ROL8__(v2, 21);
            v8 = __ROL8__(v8, 32);
            v2 ^= v11;
            v11 ^= v10;
            v8 ^= 255;
            v11 += v7;
            v8 += v2;
            v7 = __ROL8__(v7, 13);
            v7 ^= v11;
            v2 = __ROL8__(v2, 16);
            v11 = __ROL8__(v11, 32);
            v2 ^= v8;
            v8 += v7;
            v7 = __ROL8__(v7, 17);
            v11 += v2;
            v7 ^= v8;
            v2 = __ROL8__(v2, 21);
            v2 ^= v11;
            v8 = __ROL8__(v8, 32);
            v11 += v7;
            v8 += v2;
            v7 = __ROL8__(v7, 13);
            v7 ^= v11;
            v2 = __ROL8__(v2, 16);
            v11 = __ROL8__(v11, 32);
            v2 ^= v8;
            v8 += v7;
            v7 = __ROL8__(v7, 17);
            v11 += v2;
            v7 ^= v8;
            v2 = __ROL8__(v2, 21);
            v2 ^= v11;
            v8 = __ROL8__(v8, 32);
            v11 += v7;
            v8 += v2;
            v7 = __ROL8__(v7, 13);
            v7 ^= v11;
            v2 = __ROL8__(v2, 16);
            v2 ^= v8;
            v8 += v7;
            v7 = __ROL8__(v7, 17);
            v2 = __ROL8__(v2, 21);
            v11 = v8;
            v11 = __ROL8__(v11, 32);
            v11 ^= v7;
            v11 ^= v2;
        } while (v11 == v8);
        v11 ^= v8;
        a1 = ptr->field_58;
        xmm0 = _mm_loadu_si128((__m128i *)a2);
        xmm1 = _mm_loadu_si128((__m128i *)(a2 + 16));
        _mm_storeu_si128((__m128i *)(ptr2 + 296), xmm1);
        _mm_storeu_si128((__m128i *)(ptr2 + 280), xmm0);
        a2 = (struct Struct_2_t *)v_30;
        ptr2->field_138 = a2;
        a2 = (struct Struct_2_t *)v_27;
        ptr2->field_140 = a2;
        *(__int64 *)ptr2 = (__int64)(0);
        ptr2->field_8 = result;
        ptr2->field_80 = 0;
        ptr2->field_88 = result;
        result = v_28;
        ptr2->field_100 = result;
        ptr2->field_108 = v11;
        ptr2->field_110 = a1;
        result = ptr->field_10;
        result <<= 1;
        if (result != 0) {
            ptr = ptr->field_18;
            off_140108030(a1, a2, 0x7465646279746573, 0x6C7967656E657261);
            a1 = (struct Struct_1_t *)result;
            a2 = 0;
            JUMPOUT(off_140108038);
        } else {
            return result;
        }
    }
    sub_1400F3340(8, 0x5F0, ptr);
    ptr = (struct Struct_3_t *)a1;
    ptr2 = a1->field_200;
    v9 = a1->field_208;
    if (v9 == 0) JUMPOUT(0x14001f1ac);
    v2 = ptr2 + 24;
    return sub_14001F199();
}