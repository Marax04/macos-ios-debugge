// inferred from 2 accesses on `a1`
struct Struct_1_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
};

// inferred from 6 accesses on `a2`
struct Struct_2_t {
    int field_0; // offset 0
    char field_4; // offset 4
    char field_5; // offset 5
    char field_6; // offset 6
    char field_7; // offset 7
    __int64 field_8; // offset 8
};

__int64 sub_1400F87E0();
extern __int64 off_1401190A3;

__int64 __fastcall sub_14007B540(struct Struct_1_t *a1,struct Struct_2_t *a2, __int64 a3, __int64 a4) {
    __int64 *result;
    __int64 v6;
    __int64 v2;
    __int64 i;
    __int64 *src;
    __int64 v3;
    int v10;
    __int64 v7;
    __int64 v9;
    __int64 v8;

    if (a2->field_4 != 6) {
        result = a2->field_5;
        result = (__int64 *)((__int64)(__int64)result & 7);
        v6 = &off_1401190A3;
        v2 = *(result + v6);
        i = ((__int64 *)a1)[2];
        if (i == a1->field_0) JUMPOUT(0x14007b6ae);
        result = a1->field_8;
        src = i + i*2;
        src = (__int64 *)((__int64)(__int64)src << 4);
        a4 = 0x8000000000000000;
        *(__int64 *)((__int64)result + (__int64)src) = a4;
        *(__int64 *)((__int64)result + (__int64)src + 8) = 0;
        *(__int64 *)((__int64)result + (__int64)src + 9) = v2;
    } else {
        i = ((__int64 *)a1)[2];
        if (i == a1->field_0) {
            v3 = (__int64)a1;
            v2 = (__int64)a2;
            sub_1400F87E0(a1, a2, a3, a4);
            a1 = (struct Struct_1_t *)v3;
            a2 = (struct Struct_2_t *)v2;
        }
        result = a1->field_8;
        src = i + i*2;
        src = (__int64 *)((__int64)(__int64)src << 4);
        a4 = 0x8000000000000000;
        *(__int64 *)((__int64)result + (__int64)src) = a4;
        *(__int64 *)((__int64)result + (__int64)src + 8) = 1;
        *(__int64 *)((__int64)result + (__int64)src + 16) = 0;
    }
    *(__int64 *)((__int64)result + (__int64)src + 24) = 7;
    ++i;
    ((__int64 *)a1)[2] = (__int64)(i);
    if (a2->field_6 != 6) {
        a3 = a2->field_7;
        a3 &= 7;
        a4 = &off_1401190A3;
        v10 = *(src + a4);
        v2 = a2->field_8;
        if (i == a1->field_0) JUMPOUT(0x14007b6c4);
        v7 = i + i*2;
        v7 <<= 4;
        v9 = 0x8000000000000001;
        *(result + v7) = v9;
        *(result + v7 + 8) = 0;
        *(result + v7 + 9) = v10;
        *(result + v7 + 24) = 1;
        *(result + v7 + 32) = v2;
        *(result + v7 + 40) = 518;
        *(result + v7 + 42) = 8;
        v2 = i + 1;
        ((__int64 *)a1)[2] = (__int64)(v2);
        if (v2 == a1->field_0) JUMPOUT(0x14007b6de);
        result = a1->field_8;
        v8 = v2 + v2*2;
        v8 <<= 4;
        *(result + v8) = v9;
        *(result + v8 + 8) = 0x700;
        *(result + v8 + 24) = 0x600;
        *(result + v8 + 40) = 7;
        *(result + v8 + 42) = 8;
        i += 2;
        ((__int64 *)a1)[2] = (__int64)(i);
    }
    result = a2->field_0;
    return (__int64)result;
}