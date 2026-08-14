// inferred from 2 accesses on `a1`
struct Struct_1_t {
    char _pad_start[16];
    int field_10; // offset 16
    __int64 field_14; // offset 20
};

// inferred from 2 accesses on `ptr`
struct Struct_2_t {
    char field_0; // offset 0
    __int64 field_1; // offset 1
};

__int64 sub_140011B29();
extern __int64 off_140120F88;

__int64 __fastcall sub_140011970(struct Struct_1_t *a1, __int64 a2, int *a3, int a4) {
    int arg_70;
    int arg_78;
    int v_10;
    int v_20;
    __int64 v_28;
    int v_8;
    char *dst;
    struct Struct_2_t *ptr;
    __int64 v6;
    __int64 v3;
    __int64 *src;
    int v8;
    __int64 result;
    __int64 v2;
    __int64 v7;

    ptr = (struct Struct_2_t *)a3;
    v6 = arg_78;
    if (a2 == 0) {
        v3 = v6 + 1;
        src = a1->field_10;
        v8 = 45;
        if (((__int64)src & 0x800000) != 0) {
            result = 0;
            if (a4 != 0) {
                result = (ptr->field_0 >= 192) ? 1 : 0;
                if (a4 != 1) {
                    a2 = 0;
                    a2 = (ptr->field_1 >= 192) ? 1 : 0;
                    result += a2;
                }
            }
            v3 += result;
        } else {
            ptr = 0;
        }
        v2 = arg_70;
        v_8 = v2;
        v7 = a1->field_14;
        if (v3 >= v7) JUMPOUT(0x140011a46);
        v_10 = v6;
        if (((__int64)src & 0x1000000) != 0) JUMPOUT(0x140011a8f);
        a3 = (int *)v7;
        a3 -= v3;
        result = (__int64)src;
        result >>= 29;
        result &= 3;
        src = &off_140120F88;
        v2 = *(src + v2*4);
        v2 += (__int64)src;
        v_28 = (__int64)ptr;
        v_20 = a4;
        *dst = a3;
        JUMPOUT(v2);
        result = (__int64)a3;
        return sub_140011B29();
    } else {
        src = a1->field_10;
        v3 = (__int64)src;
        v3 &= 0x200000;
        result = 0x110000;
        v8 = 43;
        if (v3 == 0) v8 = result;
        v3 >>= 21;
        v3 += v6;
        if (((__int64)src & 0x800000) == 0) {
            return v3;
        } else {
            return v3;
        }
        return v3;
    }
    return result;
}