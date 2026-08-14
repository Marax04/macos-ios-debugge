// inferred from 3 accesses on `ptr`
struct Struct_1_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
};

__int64 sub_1400F2D20();
__int64 sub_14002EDF0();
__int64 sub_1400F3326();
__int64 sub_1400D5BD0();
__int64 sub_1400F27F0();
__int64 off_140108030();
extern __int64 off_140108038;

__int64 __fastcall sub_1400E43D0(int *a1, int a2, int a3) {
    __int64 rsp;
    int v_20;
    int v_28;
    __int64 v_30;
    int v_38;
    int v10;
    __int64 *src;
    struct Struct_1_t *ptr;
    __int64 *result;
    __int64 v4;
    __int64 *dst;
    __int64 *dst2;
    __int64 v6;
    __int64 v7;
    __int64 v9;

    v10 = a3;
    src = (__int64 *)a2;
    ptr = (struct Struct_1_t *)a1;
    result = *a1;
    v4 = a1[2];
    result -= v4;
    if (result <= 2) {
        v_20 = 1;
        sub_1400F2D20(ptr, v4, 3, 1);
        v4 = ptr->field_10;
    }
    dst = ptr->field_8;
    *(dst + v4 + 2) = 205;
    *(dst + v4) = 0xFF49;
    v4 += 3;
    ptr->field_10 = v4;
    sub_14002EDF0(0, 8);
    if (result == 0) {
        sub_1400F3326(1, 8);
        ptr = (struct Struct_1_t *)a1;
        --a2;
        src = (__int64 *)a2;
        src = (__int64 *)((__int64)(__int64)src << 19);
        src += 0x370C634B;
        result = *a1;
        v4 = a1[2];
        result -= v4;
        if (result <= 3) {
            do {
                v_20 = 1;
                sub_1400F2D20(ptr, v4, 4, 1);
                v4 = ptr->field_10;
            } while (true);
        }
        dst2 = ptr->field_8;
        *(dst2 + v4) = src;
        v4 += 4;
        ptr->field_10 = v4;
        sub_14002EDF0(0, 7);
        if (result == 0) JUMPOUT(0x1400e4613);
        src = result;
        *result = 0x4C68349;
        result = ptr->field_0;
        result -= v4;
        if (result <= 3) JUMPOUT(0x1400e45e9);
        result = *src;
        *(dst2 + v4) = result;
        v4 += 4;
        ptr->field_10 = v4;
        off_140108030();
        a1 = (int *)result;
        a2 = 0;
        v6 = (__int64)src;
        JUMPOUT(off_140108038);
    } else {
        v_28 = 8;
        v_30 = (__int64)result;
        *result = 0x8B4A;
        v_38 = 2;
        v_20 = v10;
        a1 = rsp + 40;
        sub_1400D5BD0(a1, src, 5, 3);
        v7 = v_28;
        src = (__int64 *)v_30;
        v9 = v_38;
        result = ptr->field_0;
        result -= v4;
        if (v9 > result) {
            v_20 = 1;
            sub_1400F2D20(ptr, v4, v9, 1);
            dst = ptr->field_8;
            v4 = ptr->field_10;
        }
        dst += v4;
        sub_1400F27F0(dst, src, v9);
        v4 += v9;
        ptr->field_10 = v4;
        if (v7 != 0) {
            off_140108030();
            a1 = (int *)result;
            a2 = 0;
            a3 = (int)src;
            JUMPOUT(off_140108038);
        }
        return (__int64)result;
    }
}