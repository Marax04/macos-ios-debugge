// inferred from 8 accesses on `ptr`
struct Struct_1_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
    __int64 field_18; // offset 24
    char _pad_18[32];
    __int64 field_40; // offset 64
    char _pad_40[16];
    __int64 field_58; // offset 88
    char _pad_58[8];
    __int64 field_68; // offset 104
    char _pad_68[24];
    __int64 field_88; // offset 136
};

// inferred from 3 accesses on `ptr2`
struct Struct_2_t {
    int field_0; // offset 0
    char _pad_0[1];
    char field_5; // offset 5
    __int64 field_6; // offset 6
};

__int64 sub_1400F3869();
__int64 sub_14001F160();
__int64 sub_1400377D0();
__int64 sub_140037910();
__int64 sub_14001F5E7();
__int64 sub_1400F6B50();
__int64 sub_1400F6820();
__int64 sub_1400F3B80();
__int64 off_140108258();
extern __int64 off_140110338;
extern __int64 off_140108030;
extern __int64 off_140108038;
extern __int64 off_14012D268;
extern __int64 off_140110350;
extern __int64 off_14011D418;
extern __int64 off_1401106F0;

__int64 __fastcall sub_14001F3F0(__int64 *a1, int a2) {
    __int64 v_20;
    int v_38;
    char *str;
    __int64 *result;
    __int64 v7;
    struct Struct_1_t *ptr;
    struct Struct_2_t *ptr2;
    __int64 v6;
    __int64 v11;
    __int64 v8;
    __int64 v9;
    __int64 *dst;
    __int64 v10;
    int v12;
    __int64 v5;

    result = a1[2];
    if (a2 >= result) {
        v7 = &off_140110338;
        sub_1400F3869(a2, result, v7);
        ptr = (struct Struct_1_t *)a1;
        result = a1[4];
        *result = *result - 1;
        if ((*result == 0)) JUMPOUT(0x14001f651);
        result = ptr->field_40;
        result = (__int64 *)((__int64)(__int64)result << 1);
        if (result != 0) JUMPOUT(0x14001f66a);
        result = ptr->field_68;
        *result = *result - 1;
        if ((*result == 0)) JUMPOUT(0x14001f690);
        result = ptr->field_58;
        *result = *result - 1;
        if ((*result == 0)) JUMPOUT(0x14001f6a7);
        result = ptr->field_88;
        *result = *result - 1;
        if (!((*result != 0))) {
            a1 = ptr->field_88;
            sub_14001F160(a1);
        }
        ptr2 = ptr + 24;
        sub_1400377D0(ptr2);
        result = ptr->field_18;
        if (result != 0) {
            *result = *result - 1;
            if (!((*result != 0))) {
                sub_140037910(ptr2);
            }
        }
        ptr2 = ptr->field_8;
        v6 = ptr->field_10;
        if (v6 == 0) JUMPOUT(0x14001f610);
        v11 = ptr2 + 8;
        v8 = off_140108030;
        v9 = off_140108038;
        return sub_14001F5E7();
    } else {
        dst = a1;
        ptr2 = *(a1 + 8);
        a2 <<= 7;
        ptr = ptr2 + a2;
        ptr += 4;
        a1 = 1;
        result = 0;
        /* cmpxchg %(__int64)a1, 4(%(__int64)ptr2,%a2) */;
        if ((ptr != 0)) {
            v10 = a2;
            sub_1400F6B50(ptr);
        }
        ptr2 += a2;
        result = off_14012D268;
        result = (__int64 *)((__int64)(__int64)result << 1);
        if (result != 0) {
            sub_1400F6820(a1, v10);
            v10 = (__int64)result;
            v10 ^= 1;
            result = ptr2->field_5;
            if (result == 0) {
                v12 = ptr2->field_6;
                if (v12 != 0) {
                    ptr2->field_6 = 0;
                    *(__int64 *)ptr2 = (__int64)(ptr2->field_0 + 1);
                    off_140108258(ptr2, a2);
                    *(dst + 24) = *(dst + 24) - 1;
                }
                if (v10 == 0) {
                    result = off_14012D268;
                    result = (__int64 *)((__int64)(__int64)result << 1);
                    if (result != 0) {
                        sub_1400F6820();
                        if (result == 0) {
                            ptr2->field_5 = 1;
                        }
                    }
                }
                result = 0;
                { __int64 __xchg_tmp = ptr->field_0; *(__int64 *)ptr = (__int64)(result); result = __xchg_tmp; };
                if (result == 2) {
                    off_140108258(ptr);
                }
                result = (__int64 *)v12;
                return (__int64)result;
            } else {
                str = (char *)ptr;
                v_38 = v10;
                result = &off_140110350;
                v_20 = (__int64)result;
                a1 = &off_14011D418;
                v5 = &off_1401106F0;
                sub_1400F3B80(a1, 43, str, v5);
            }
            return v5;
        } else {
            v10 = 0;
            result = ptr2->field_5;
            if (result != 0) {
                return (__int64)result;
            } else {
                return (__int64)result;
            }
            return (__int64)result;
        }
        return (__int64)result;
    }
}