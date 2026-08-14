// inferred from 5 accesses on `result`
struct Struct_1_t {
    __int64 field_0; // offset 0
    char _pad_0[8];
    __int64 field_10; // offset 16
    char _pad_10[360];
    __int64 field_180; // offset 384
    char _pad_180[1680];
    __int64 field_818; // offset 0x818
    __int64 field_820; // offset 0x820
};

// inferred from 3 accesses on `ptr`
struct Struct_2_t {
    char _pad_start[128];
    __int64 field_80; // offset 128
    char _pad_80[120];
    __int64 field_100; // offset 256
    __int64 field_108; // offset 264
};

// inferred from 6 accesses on `ptr2`
struct Struct_3_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
    char _pad_8[2056];
    __int64 field_818; // offset 0x818
    __int64 field_820; // offset 0x820
    __int64 field_828; // offset 0x828
    char _pad_828[80];
    __int64 field_880; // offset 0x880
};

__int64 sub_1400F5140();
__int64 sub_14001BEA0();
__int64 sub_1400F35E0();
__int64 sub_1400F3D20();
__int64 sub_1400F4200();
extern __int64 off_14012D270;
extern __int64 off_14012D008;
extern __int64 off_14012D000;
extern __int64 off_1401177B0;

__int64 __fastcall sub_1400200C0(__int64 *a1, int *a2) {
    __int64 rsp;
    int arg_8;
    __int64 v_20;
    __int64 *v_0;
    struct Struct_2_t *ptr;
    __int64 v3;
    struct Struct_1_t *result;
    struct Struct_3_t *ptr2;
    __int64 v11;
    __int64 v5;
    __int64 v9;
    __int64 *src;
    __int64 v10;
    __int64 v7;
    __int64 v8;
    __int64 v6;

    ptr = *a2;
    v3 = ptr->field_100;
    result = off_14012D270;
    a2 = __readgsqword(88);
    result = v_0[(__int64)result];
    ptr2 = result + 8;
    result = (struct Struct_1_t *)ptr2;
    if ((result->field_10 != 1)) {
        v11 = (__int64)a1;
        sub_1400F5140(ptr2, 0, v5, v6);
        a1 = (__int64 *)v11;
        if (result != 0) {
            result = result->field_0;
            if (result->field_818 != 0) {
                *(__int64 *)rsp = *(__int64 *)rsp | 0;
            }
        } else {
            result = off_14012D008;
            if (result != 0) JUMPOUT(0x140020383);
            sub_14001BEA0(off_14012D000);
            a1 = result->field_818;
            a2 = result->field_820;
            v5 = a2 - 1;
            result->field_820 = v5;
            a2 = (int *)((__int64)(__int64)a2 ^ 1);
            a2 = (int *)((__int64)(__int64)a2 | (__int64)a1);
            if ((a2 == 0)) JUMPOUT(0x140020397);
            a1 = (__int64 *)v11;
            if ((a1 != 0)) {
                return (__int64)a1;
            } else {
            }
        }
        if (ptr2->field_8 != 1) {
            v9 = (__int64)a1;
            sub_1400F5140(ptr2, a2, v5);
            a1 = (__int64 *)v9;
            ptr2 = (struct Struct_3_t *)result;
            if (result != 0) {
                ptr2 = ptr2->field_0;
                v_20 = (__int64)ptr2;
                result = ptr2->field_818;
                if (result == -1) {
                    a1 = &off_1401177B0;
                    sub_1400F35E0(a1);
                } else {
                    a2 = result + 1;
                    ptr2->field_818 = a2;
                    if (result == 0) {
                        result = ptr2->field_8;
                        a2 = result->field_180;
                        a2 = (int *)((__int64)(__int64)a2 | 1);
                        result = 0;
                        /* cmpxchg %(__int64)a2, 0x880(%(__int64)ptr2) */;
                        result = ptr2->field_828;
                        a2 = result + 1;
                        ptr2->field_828 = a2;
                        if (((__int64)result & 127) == 0) {
                            result = ptr2->field_8;
                            result += 128;
                            a2 = rsp + 32;
                            v9 = (__int64)a1;
                            sub_1400F3D20(result, a2);
                            a1 = (__int64 *)v9;
                        }
                    }
                    result = ptr->field_108;
                    result -= v3;
                    if (result <= 0) {
                    } else {
                        result = ptr->field_80;
                        a2 = (int *)result;
                        a2 = (int *)((__int64)(__int64)a2 & -8);
                        src = *a2;
                        a2 = (int *)arg_8;
                        --a2;
                        a2 = (int *)((__int64)(__int64)a2 & v3);
                        a2 = (int *)((__int64)(__int64)a2 << 4);
                        v10 = *(__int64 *)((__int64)src + (__int64)a2);
                        src = *(__int64 *)((__int64)src + (__int64)a2 + 8);
                        v7 = ptr->field_80;
                        a2 = 2;
                        if (v7 == result) {
                            v8 = v3 + 1;
                            result = (struct Struct_1_t *)v3;
                            /* cmpxchg %v8, 256(%(__int64)ptr) */;
                            if ((0 /* unresolved: flags != */)) {
                                *a1 = a2;
                            } else {
                                *(a1 + 8) = v10;
                                a1[2] = src;
                                *a1 = 1;
                            }
                            result = ptr2->field_818;
                            a1 = result - 1;
                            ptr2->field_818 = a1;
                            if (result == 1) {
                                ptr2->field_880 = 0;
                                if (ptr2->field_820 == 0) {
                                    a1 = (__int64 *)ptr2;
                                    return sub_1400F4200();
                                }
                            }
                            return (__int64)a1;
                        }
                    }
                    return (__int64)a1;
                }
                return (__int64)a1;
            } else {
                result = off_14012D008;
                if (result != 0) JUMPOUT(0x14002038d);
                sub_14001BEA0(off_14012D000);
                ptr2 = (struct Struct_3_t *)result;
                v_20 = (__int64)result;
                result = result->field_818;
                if (result == -1) {
                    return (__int64)result;
                } else {
                    a1 = result + 1;
                    ptr2->field_818 = a1;
                    a1 = (__int64 *)v9;
                    if (result == 0) {
                        result = ptr2->field_8;
                        a2 = result->field_180;
                        a2 = (int *)((__int64)(__int64)a2 | 1);
                        result = 0;
                        /* cmpxchg %(__int64)a2, 0x880(%(__int64)ptr2) */;
                        result = ptr2->field_828;
                        a2 = result + 1;
                        ptr2->field_828 = a2;
                        if (((__int64)result & 127) == 0) JUMPOUT(0x1400203a7);
                    }
                    result = ptr2->field_820;
                    a2 = result - 1;
                    ptr2->field_820 = a2;
                    result = (struct Struct_1_t *)((__int64)(__int64)result ^ 1);
                    result = (struct Struct_1_t *)((__int64)(__int64)result | (__int64)ptr2->field_818);
                    if (!((result != 0))) {
                        sub_1400F4200(ptr2, a2);
                        return (__int64)result;
                    }
                    return (__int64)result;
                }
                return (__int64)result;
            }
            return (__int64)result;
        }
        return (__int64)result;
    }
    return (__int64)result;
}