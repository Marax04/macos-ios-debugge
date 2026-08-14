// inferred from 2 accesses on `a1`
struct Struct_1_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
};

// inferred from 3 accesses on `ptr`
struct Struct_2_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
};

__int64 sub_1400F2D20();
__int64 sub_14002EDF0();
__int64 sub_1400F3326();
__int64 off_140108030();
extern __int64 off_140108038;

__int64 __fastcall sub_1400E4530(struct Struct_1_t *a1, int a2) {
    int v_20;
    struct Struct_2_t *ptr;
    __int64 *src;
    __int64 *result;
    __int64 v4;
    __int64 *dst;
    __int64 *dst2;
    __int64 v6;

    ptr = (struct Struct_2_t *)a1;
    --a2;
    src = (__int64 *)a2;
    src = (__int64 *)((__int64)(__int64)src << 19);
    src += 0x370C634B;
    result = a1->field_0;
    v4 = ((__int64 *)a1)[2];
    result -= v4;
    if (result <= 3) {
        do {
            v_20 = 1;
            sub_1400F2D20(ptr, v4, 4, 1);
            v4 = ptr->field_10;
        } while (true);
    }
    dst = ptr->field_8;
    *(dst + v4) = src;
    v4 += 4;
    ptr->field_10 = v4;
    sub_14002EDF0(0, 7);
    if (result != 0) {
        src = result;
        *result = 0x4C68349;
        result = ptr->field_0;
        result -= v4;
        if (result <= 3) {
            v_20 = 1;
            sub_1400F2D20(ptr, v4, 4, 1);
            dst = ptr->field_8;
            v4 = ptr->field_10;
        }
        result = *src;
        *(dst + v4) = result;
        v4 += 4;
        ptr->field_10 = v4;
        off_140108030();
        a1 = (struct Struct_1_t *)result;
        a2 = 0;
        dst2 = src;
        JUMPOUT(off_140108038);
    }
    sub_1400F3326(1, 7);
    result = a1->field_0;
    a2 = ((__int64 *)a1)[2];
    dst2 = result;
    dst2 -= a2;
    if (dst2 <= 2) JUMPOUT(0x1400e483b);
    dst2 = a1->field_8;
    *(dst2 + a2 + 2) = 200;
    *(dst2 + a2) = 328;
    a2 += 3;
    ((__int64 *)a1)[2] = (__int64)(a2);
    v6 = (__int64)result;
    v6 -= a2;
    if (v6 <= 3) JUMPOUT(0x1400e4867);
    *(dst2 + a2) = 0xDC1C148;
    a2 += 4;
    ((__int64 *)a1)[2] = (__int64)(a2);
    result -= a2;
    if (result <= 2) JUMPOUT(0x1400e4897);
    *(dst2 + a2 + 2) = 193;
    *(dst2 + a2) = 0x3148;
    a2 += 3;
    ((__int64 *)a1)[2] = (__int64)(a2);
    result = a1->field_0;
    dst2 = result;
    dst2 -= a2;
    if (dst2 <= 3) JUMPOUT(0x1400e48c4);
    dst2 = a1->field_8;
    *(dst2 + a2) = 0x20C0C148;
    a2 += 4;
    ((__int64 *)a1)[2] = (__int64)(a2);
    v6 = (__int64)result;
    v6 -= a2;
    if (v6 <= 2) JUMPOUT(0x1400e48f0);
    *(dst2 + a2 + 2) = 218;
    *(dst2 + a2) = 328;
    a2 += 3;
    ((__int64 *)a1)[2] = (__int64)(a2);
    result -= a2;
    if (result <= 3) JUMPOUT(0x1400e4920);
    *(dst2 + a2) = 0x10C3C148;
    a2 += 4;
    ((__int64 *)a1)[2] = (__int64)(a2);
    result = a1->field_0;
    dst2 = result;
    dst2 -= a2;
    if (dst2 <= 2) JUMPOUT(0x1400e494d);
    dst2 = a1->field_8;
    *(dst2 + a2 + 2) = 211;
    *(dst2 + a2) = 0x3148;
    a2 += 3;
    ((__int64 *)a1)[2] = (__int64)(a2);
    v6 = (__int64)result;
    v6 -= a2;
    if (v6 <= 2) JUMPOUT(0x1400e4979);
    *(dst2 + a2 + 2) = 216;
    *(dst2 + a2) = 328;
    a2 += 3;
    ((__int64 *)a1)[2] = (__int64)(a2);
    result -= a2;
    if (result <= 3) JUMPOUT(0x1400e49a9);
    *(dst2 + a2) = 0x15C3C148;
    a2 += 4;
    ((__int64 *)a1)[2] = (__int64)(a2);
    result = a1->field_0;
    dst2 = result;
    dst2 -= a2;
    if (dst2 <= 2) JUMPOUT(0x1400e49d6);
    dst2 = a1->field_8;
    *(dst2 + a2 + 2) = 195;
    *(dst2 + a2) = 0x3148;
    a2 += 3;
    ((__int64 *)a1)[2] = (__int64)(a2);
    v6 = (__int64)result;
    v6 -= a2;
    if (v6 <= 2) JUMPOUT(0x1400e4a02);
    *(dst2 + a2 + 2) = 202;
    *(dst2 + a2) = 328;
    a2 += 3;
    ((__int64 *)a1)[2] = (__int64)(a2);
    result -= a2;
    if (result <= 3) JUMPOUT(0x1400e4a32);
    *(dst2 + a2) = 0x11C1C148;
    a2 += 4;
    ((__int64 *)a1)[2] = (__int64)(a2);
    result = a1->field_0;
    dst2 = result;
    dst2 -= a2;
    if (dst2 <= 2) JUMPOUT(0x1400e4a5f);
    dst2 = a1->field_8;
    *(dst2 + a2 + 2) = 209;
    *(dst2 + a2) = 0x3148;
    a2 += 3;
    ((__int64 *)a1)[2] = (__int64)(a2);
    result -= a2;
    if (result <= 3) JUMPOUT(0x1400e4a8b);
    *(dst2 + a2) = 0x20C2C148;
    a2 += 4;
    ((__int64 *)a1)[2] = (__int64)(a2);
    return (__int64)result;
}