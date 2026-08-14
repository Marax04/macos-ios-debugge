// inferred from 3 accesses on `ptr`
struct Struct_1_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
};

// inferred from 2 accesses on `ptr2`
struct Struct_2_t {
    char _pad_start[2];
    char field_2; // offset 2
    __int64 field_3; // offset 3
};

__int64 sub_14002EDF0();
__int64 sub_1400F3326();
__int64 sub_1400F2D20();
__int64 sub_1400D5BD0();
__int64 sub_1400F27F0();
__int64 off_140108030();
extern __int64 off_140108038;

__int64 __fastcall sub_1400E3F00(int *a1, int a2) {
    __int64 rsp;
    int v_20;
    int v_30;
    __int64 v_38;
    int v_40;
    __int64 v4;
    struct Struct_1_t *ptr;
    __int64 *src;
    struct Struct_2_t *ptr2;
    __int64 *dst;
    __int64 result;
    __int64 v5;
    __int64 v8;
    __int64 v6;
    __int64 v9;
    __int64 *dst2;

    v4 = a2;
    ptr = (struct Struct_1_t *)a1;
    sub_14002EDF0(0, 8);
    if (ptr2 == 0) {
        sub_1400F3326(1, 8);
    } else {
        src = (__int64 *)ptr2;
        *(__int64 *)ptr2 = (__int64)(0x8B4B);
        v4 <<= 3;
        v4 |= 4;
        ptr2->field_2 = v4;
        ptr2->field_3 = 55;
        ptr2 = ptr->field_0;
        v4 = ptr->field_10;
        ptr2 -= v4;
        if (ptr2 <= 3) {
            do {
                v_20 = 1;
                sub_1400F2D20(ptr, v4, 4, 1);
                v4 = ptr->field_10;
            } while (true);
        }
        dst = ptr->field_8;
        result = *src;
        *(dst + v4) = result;
        v4 += 4;
        ptr->field_10 = v4;
        off_140108030();
        ((__int64 (*)())off_140108038)(ptr2, 0, src);
        sub_14002EDF0(0, 7);
        if (ptr2 != 0) {
            src = (__int64 *)ptr2;
            *(__int64 *)ptr2 = (__int64)(0x8C68349);
            ptr2 = ptr->field_0;
            ptr2 -= v4;
            if (ptr2 <= 3) {
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
            a1 = (int *)ptr2;
            a2 = 0;
            v5 = (__int64)src;
            JUMPOUT(off_140108038);
        }
    }
    sub_1400F3326(1, 7);
    v4 = v5;
    src = (__int64 *)a2;
    ptr = (struct Struct_1_t *)a1;
    sub_14002EDF0(0, 8);
    if (ptr2 == 0) JUMPOUT(0x1400e416c);
    v_30 = 8;
    v_38 = (__int64)ptr2;
    *(__int64 *)ptr2 = (__int64)(0x894A);
    v_40 = 2;
    v_20 = v4;
    a1 = rsp + 48;
    sub_1400D5BD0(a1, src, 5, 3);
    v8 = v_30;
    src = (__int64 *)v_38;
    v6 = v_40;
    v9 = ptr->field_0;
    v4 = ptr->field_10;
    v9 -= v4;
    if (v6 > v9) JUMPOUT(0x1400e411c);
    dst2 = ptr->field_8;
    a1 = dst2 + v4;
    sub_1400F27F0(a1, src, v6);
    v4 += v6;
    ptr->field_10 = v4;
    if (v8 != 0) {
        off_140108030();
        ((__int64 (*)())off_140108038)(v9, 0, src);
    }
    result = ptr->field_0;
    result -= v4;
    if (result <= 2) JUMPOUT(0x1400e4142);
    *(dst2 + v4 + 2) = 197;
    *(dst2 + v4) = 0xFF49;
    v4 += 3;
    ptr->field_10 = v4;
    return result;
}