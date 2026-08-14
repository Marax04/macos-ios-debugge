// inferred from 3 accesses on `ptr`
struct Struct_1_t {
    __int64 field_0; // offset 0
    char _pad_0[8];
    __int64 field_10; // offset 16
    __int64 field_18; // offset 24
};

// inferred from 13 accesses on `ptr2`
struct Struct_2_t {
    char _pad_start[8];
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
    __int64 field_18; // offset 24
    __int64 field_20; // offset 32
    __int64 field_28; // offset 40
    __int64 field_30; // offset 48
    char _pad_30[16];
    __int64 field_48; // offset 72
    char _pad_48[16];
    __int64 field_60; // offset 96
    __int64 field_68; // offset 104
    __int64 field_70; // offset 112
    __int64 field_78; // offset 120
    __int64 field_80; // offset 128
    __int64 field_88; // offset 136
};

__int64 sub_140054AA0();
__int64 sub_140058CB0();
__int64 sub_1400F3360();
__int64 sub_14002EDF0();
__int64 sub_140058C93();
__int64 sub_1400F27F0();
__int64 sub_140059030();
__int64 sub_1400F3326();
__int64 off_140108030();
__int64 off_140108038();

__int64 __fastcall sub_140058820(int *a1, size_t *a2) {
    __int64 rsp;
    int v_28;
    int v_30;
    int v_38;
    int v_40;
    int v_48;
    int v_50;
    int v_58;
    int v_60;
    int v_68;
    int v_70;
    int v_78;
    int v_80;
    int v_88;
    int v_98;
    int v_a0;
    struct Struct_1_t *ptr;
    struct Struct_2_t *ptr2;
    __int64 v9;
    __int64 v8;
    __int64 v11;
    __int64 result;
    __int64 v12;
    __int64 *src;
    __int64 v6;
    __int64 i;
    __int64 v5;
    __int64 v7;

    ptr = (struct Struct_1_t *)a2;
    ptr2 = (struct Struct_2_t *)a1;
    v9 = *a2;
    v8 = a2[2];
    v_88 = 0;
    v_98 = 0;
    v_a0 = 0x920;
    a1 = rsp + 72;
    a2 = rsp + 136;
    sub_140054AA0(a1, a2, ptr);
    v11 = v_48;
    if (v11 == 3) {
        result = ptr->field_18;
        v11 = 1;
        if (result != 0) {
            v12 = ptr->field_0;
            src = ptr->field_10;
            a1 = *src;
            if (a1 == 34) {
                v_78 = v8;
                a1 = rsp + 72;
                sub_140058CB0(a1, ptr);
                v11 = v_48;
                v6 = v_50;
                i = v_60;
                if (v11 != 3) {
                    v_30 = v12;
                    v_38 = v9;
                    v5 = v_58;
                    v9 = v_68;
                    v12 = v_70;
                    result = v6;
                    result >>= 8;
                    if (v11 != 3) {
                        src = (__int64 *)i;
                        result <<= 8;
                        i = v8;
                        i |= result;
                        v7 = v5;
                    } else {
                        v_28 = v5;
                        a1 = ptr->field_0;
                        v_80 = (int)a1;
                        a1 = ptr->field_10;
                        v_40 = (int)a1;
                        result <<= 8;
                        v6 |= result;
                        v12 = ptr->field_0;
                        v9 = ptr->field_10;
                        v_88 = 0;
                        v_98 = 0;
                        v_a0 = 0x920;
                        a1 = rsp + 72;
                        a2 = rsp + 136;
                        sub_140054AA0(a1, a2, ptr);
                        v11 = v_48;
                        if (v11 != 3) {
                            i = v_50;
                            v7 = v_58;
                            src = (__int64 *)v_60;
                            v9 = v_68;
                            v12 = v_70;
                            if (v6 != 0) {
                                off_140108030(a1, a2);
                                v5 = v_28;
                                off_140108038(result, 0, v5);
                            }
                        } else {
                            a2 = (size_t *)v_78;
                            a2 -= v_38;
                            src -= v_30;
                            v9 -= v12;
                            v12 = ptr->field_10;
                            v12 -= ptr->field_0;
                            result = v6;
                            result = -result;
                            if ((0 /* overflow check on (-result) */)) {
                                a1 = (int *)v_40;
                                a1 -= v_80;
                                *(__int64 *)ptr2 = (__int64)(v6);
                                result = v_28;
                                ptr2->field_8 = result;
                                ptr2->field_10 = i;
                                result = 0x8000000000000002;
                                ptr2->field_18 = result;
                                ptr2->field_20 = src;
                                ptr2->field_28 = a1;
                                a1 = 0x8000000000000003;
                                ptr2->field_30 = a1;
                                ptr2->field_48 = a1;
                                ptr2->field_60 = result;
                                ptr2->field_68 = a2;
                                ptr2->field_70 = src;
                                ptr2->field_78 = result;
                                ptr2->field_80 = v9;
                                ptr2->field_88 = v12;
                            } else {
                                v11 = v_28;
                                v7 = (__int64)a2;
                                ptr2->field_8 = v11;
                                ptr2->field_10 = i;
                                ptr2->field_18 = v7;
                                ptr2->field_20 = src;
                                ptr2->field_28 = v9;
                                ptr2->field_30 = v12;
                                result = 0x8000000000000000;
                                *(__int64 *)ptr2 = (__int64)(result);
                            }
                            return result;
                        }
                    }
                    return result;
                } else {
                    if (i < 0) {
                        sub_1400F3360(a1, a2);
                        v9 = 0;
                        i = 0;
                        v8 = 0;
                        result = 0;
                    } else {
                        result = v_58;
                        v_40 = result;
                        if (i == 0) JUMPOUT(0x140058c46);
                        sub_14002EDF0(0, i);
                        a1 = (int *)result;
                        if (result != 0) JUMPOUT(0x140058c4b);
                        return sub_140058C93();
                    }
                }
                return (__int64)a1;
            } else {
                if (a1 != 39) {
                    i = 0;
                    do {
                        a1 = *(src + i);
                        a2 = a1 - 48;
                        ++i;
                    } while (result != i);
                    i = result;
                    if (i != 0) {
                        v11 = src + i;
                        result -= i;
                        ptr->field_10 = v11;
                        ptr->field_18 = result;
                        if (i >= 0) {
                            v_78 = v8;
                            sub_14002EDF0(0, i, v5);
                            if (result == 0) JUMPOUT(0x140058c93);
                            v_40 = v11;
                            v_38 = v9;
                            v_28 = result;
                            sub_1400F27F0(result, src, i);
                            result = i;
                            result >>= 8;
                            v_30 = v12;
                            v_80 = v12;
                            v6 = i;
                            return v6;
                        } else {
                            return v6;
                        }
                        return v6;
                    }
                } else {
                    v_78 = v8;
                    a1 = rsp + 72;
                    sub_140059030(a1, ptr, 8);
                    v11 = v_48;
                    v6 = v_58;
                    if (v11 != 3) {
                        v_30 = v12;
                        v_38 = v9;
                        v5 = v6;
                        v6 = v_50;
                        i = v_60;
                        return i;
                    } else {
                        if (v6 < 0) {
                            return i;
                        } else {
                            i = v_50;
                            v_38 = v9;
                            v_30 = v12;
                            if (v6 == 0) {
                            } else {
                                sub_14002EDF0(0, v6);
                                a1 = (int *)result;
                                if (result != 0) {
                                    i = (__int64)a1;
                                    sub_1400F27F0(1, i, v6);
                                    v5 = i;
                                    i = v6;
                                    return i;
                                } else {
                                    sub_1400F3326(1, v6);
                                    i = v_50;
                                    v7 = v_58;
                                    src = (__int64 *)v_60;
                                    v9 = v_68;
                                    v12 = v_70;
                                }
                                return v12;
                            }
                            return v12;
                        }
                        return v12;
                    }
                    return v12;
                }
                return v12;
            }
            return v12;
        }
        return v12;
    }
    return result;
}