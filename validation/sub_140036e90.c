// inferred from 2 accesses on `ptr`
struct Struct_1_t {
    char _pad_start[8];
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
};

// inferred from 2 accesses on `ptr2`
struct Struct_2_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
};

__int64 sub_14002EDF0();
__int64 sub_1400F3340();
__int64 sub_140037030();
__int64 off_1401081A0();
__int64 off_140108030();
__int64 off_140108038();
__int64 off_140108060();
extern __int64 off_1400370E0;

__int64 __fastcall sub_140036E90(int a1, int a2, __int64 a3) {
    __int64 rsp;
    __int64 v_10;
    __int64 v_18;
    __int64 v_20;
    int v_28;
    int v_8;
    __int64 v11;
    __int64 *src;
    __int64 v9;
    __int64 v3;
    struct Struct_2_t *ptr2;
    __int64 v5;
    __int64 v7;
    __int64 *src2;
    struct Struct_1_t *ptr;
    __int64 result;
    __int64 *dst;

    v11 = rsp + 80;
    v_8 = -2;
    src = (__int64 *)a3;
    v9 = a2;
    v3 = a1;
    sub_14002EDF0(0, 16);
    if (dst == 0) {
        v_10 = v9;
        v_18 = (__int64)src;
        sub_1400F3340(8, 16);
        v_10 = a2;
        v11 = a2 + 80;
        a1 = v_10;
        a2 = v_18;
        return sub_140037030(a1, a2);
    } else {
        ptr2 = (struct Struct_2_t *)dst;
        *dst = v9;
        *(dst + 8) = src;
        v_28 = 0;
        v_20 = 0x10000;
        v5 = &off_1400370E0;
        src = 0;
        off_1401081A0(0, v3, v5);
        if (dst == 0) {
            v7 = ptr2->field_0;
            v_18 = v7;
            v_20 = (__int64)ptr2;
            src2 = ptr2->field_8;
            v_10 = (__int64)src2;
            src2 = *src2;
            if (src2 != 0) {
                a1 = v_18;
                ((__int64 (*)())src2)(a1, src2);
            }
            src = (__int64 *)v_18;
            ptr = (struct Struct_1_t *)v_10;
            v3 = v_20;
            if (ptr->field_8 != 0) {
                if (ptr->field_10 >= 17) {
                    src = *(src - 8);
                }
                off_140108030();
                off_140108038(ptr, 0, src);
            }
            off_140108030();
            off_140108038(ptr, 0, v3);
            off_140108060();
            a2 = result;
            a2 <<= 32;
            a2 |= 2;
            src = 1;
        }
        result = (__int64)src;
        return result;
    }
}