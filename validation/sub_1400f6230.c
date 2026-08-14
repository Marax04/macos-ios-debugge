// inferred from 2 accesses on `a1`
struct Struct_1_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
};

// inferred from 2 accesses on `ptr`
struct Struct_2_t {
    __int64 field_0; // offset 0
    char _pad_0[8];
    __int64 field_10; // offset 16
};

__int64 sub_1400F3600();
__int64 sub_1400F5F40();
extern __int64 off_140111F88;
extern __int64 off_140111CF2;
extern __int64 off_140111AF2;
extern __int64 off_14012D020;
extern __int64 off_140111F70;
extern __int64 off_14012D018;

__int64 __fastcall sub_1400F6230(struct Struct_1_t *a1, __int64 a2) {
    int v_20;
    __int64 v_22;
    int v_28;
    struct Struct_2_t *ptr;
    __int64 v2;
    __int64 v6;
    __int64 v4;
    __int64 *result;
    __int64 v5;
    __int64 *src;
    __int64 *src2;
    __int64 v9;
    __int64 v10;

    ptr = ((__int64 *)a1)[2];
    v2 = a1->field_8;
    if (ptr > v2) {
        v6 = &off_140111F88;
        sub_1400F3600(0, ptr, v2, v6);
        v4 = a1->field_8;
        v2 = ((__int64 *)a1)[2];
        result = (__int64 *)v4;
        result -= v2;
        if ((result < 0)) JUMPOUT(0x1400f66bf);
        ptr = (struct Struct_2_t *)a1;
        if (result <= 3) JUMPOUT(0x1400f6571);
        result = ptr->field_0;
        a1 = *(result + v2);
        v5 = *(result + v2 + 1);
        v6 = *(result + v2 + 2);
        result = *(result + v2 + 3);
        v2 += 4;
        ptr->field_10 = v2;
        src = &off_140111CF2;
        src2 = &off_140111AF2;
        v5 = *(src2 + v5*2);
        v6 = *(src + v6*2);
        src2 = *(src2 + (__int64)(__int64)result*2);
        v5 |= *(src + (__int64)(__int64)a1*2);
        result = (__int64 *)v5;
        result = (__int64 *)((__int64)(__int64)result << 8);
        result = (__int64 *)((__int64)(__int64)result | v6);
        result = (__int64 *)((__int64)(__int64)result | (__int64)src2);
        if ((result < 0)) JUMPOUT(0x1400f659e);
        v_22 = (__int64)result;
        v_20 = 0;
        if (v_20 != 1) JUMPOUT(0x1400f6379);
        result = (__int64 *)v_28;
        return (__int64)result;
    } else {
        v4 = a2;
        v9 = a1->field_0;
        v5 = v9 + ptr;
        result = off_14012D020;
        ((__int64 (*)())result)(10, v9, v5);
        if (((__int64)result & 1) != 0) {
            a2 -= v9;
            v10 = a2 + 1;
            if (a2 >= v2) {
                v6 = &off_140111F70;
                sub_1400F3600(0, v10, v2, v6);
                v10 = 0;
            }
            v5 = v9 + v10;
            result = off_14012D018;
            ((__int64 (*)())result)(10, v9, v5);
            a2 = result + 1;
            ptr -= v10;
            a1 = (struct Struct_1_t *)v4;
            v5 = (__int64)ptr;
            return sub_1400F5F40();
        }
        return (__int64)result;
    }
}