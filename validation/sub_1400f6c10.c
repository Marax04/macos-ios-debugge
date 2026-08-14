// inferred from 2 accesses on `a1`
struct Struct_1_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
};

__int64 sub_1400F6940();
__int64 sub_1400F3326();
__int64 sub_1400F6D21();
extern __int64 off_140108258;

__int64 __fastcall sub_1400F6C10(struct Struct_1_t *a1) {
    __int64 rsp;
    int v_10;
    int v_18;
    int v_20;
    int v_28;
    int v_8;
    __int64 v12;
    __int64 *dst;
    __int64 v10;
    __int64 v2;
    __int64 v5;
    __int64 v6;
    __int64 v8;
    __int64 *dst2;
    __int64 result;
    int v3;
    __int64 v7;

    v12 = rsp + 80;
    dst = (__int64 *)a1;
    v10 = a1->field_0;
    v2 = v10 + v10;
    v5 = 4;
    if (v2 >= 5) v5 = v2;
    v6 = a1->field_8;
    v_28 = 16;
    v_20 = 8;
    v8 = v12 - 24;
    sub_1400F6940(v8, v10, v6);
    if (v_18 == 1) {
        dst2 = (__int64 *)v_10;
        sub_1400F3326(dst2, v_8);
        v12 = rsp + 32;
        if ((v3 & 0x3FFFFFFF) != 0) JUMPOUT(0x1400f6d29);
        result = v3;
        result = -result;
        if (!((0 /* overflow check on (-result) */))) {
            v3 = 0;
            result = 0x80000000;
            /* cmpxchg %v3, (%(__int64)dst2) */;
            if (!((0 /* unresolved: flags != */))) {
                *(dst2 + 4) = *(dst2 + 4) + 1;
                dst2 += 4;
                JUMPOUT(off_140108258);
            }
            v3 = result;
        }
        if (v3 == 0xC0000000) JUMPOUT(0x1400f6ce0);
        if (v3 != 0x40000000) JUMPOUT(0x1400f6d21);
        v3 = 0;
        result = 0x40000000;
        /* cmpxchg %v3, (%(__int64)dst2) */;
        if ((0 /* unresolved: flags == */)) JUMPOUT(0x1400f6d14);
        return sub_1400F6D21();
    } else {
        v7 = v_10;
        *(dst + 8) = v7;
        *dst = v5;
        return result;
    }
}