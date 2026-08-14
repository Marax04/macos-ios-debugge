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

__int64 sub_1400282A0();
__int64 sub_14002DC40();
extern __int64 off_140108258;

__int64 __fastcall sub_140033380(struct Struct_1_t *a1, __int64 a2, __int64 a3) {
    int v_10;
    __int64 v_8;
    char *dst;
    __int64 *result;
    struct Struct_2_t *ptr;
    __int64 *v2;
    __int64 v5;
    __int64 v6;
    __int64 v4;

    a1->field_8 = a1->field_8 - 1;
    if (!((a1->field_8 != 0))) {
        *(__int64 *)a1 = (__int64)(0);
        result = 0;
        result = _InterlockedExchange64(&a1[1], result);
        if (result == 2) {
            a1 += 12;
            JUMPOUT(off_140108258);
            *dst = -2;
            ptr = a1->field_0;
            ptr = ptr->field_0;
            if (ptr->field_10 != 0) JUMPOUT(0x14003344a);
            v2 = (__int64 *)a1;
            ptr->field_10 = -1;
            v_8 = (__int64)ptr;
            v5 = ptr + 24;
            sub_1400282A0(v5);
            v6 = 0xFFFFFFFF00000003;
            v6 &= (__int64)ptr;
            if (v6 != a2) a3 = ptr;
            result = (__int64 *)v_8;
            *(result + 16) = *(result + 16) + 1;
            if (a3 != 0) {
                v_10 = a3;
                v4 = v2 + 8;
                v_8 = v4;
                if (*(v2 + 8) != 0) {
                    sub_14002DC40(v_8, 0x600000002, 0);
                }
                a3 = v_10;
                result = (__int64 *)v_8;
                *result = a3;
            }
            result = (a3 != 0) ? 1 : 0;
            return (__int64)result;
        }
    }
    return (__int64)result;
}