// inferred from 3 accesses on `a1`
struct Struct_1_t {
    char field_0; // offset 0
    int field_1; // offset 1
    char _pad_1[3];
    __int64 field_8; // offset 8
};

// inferred from 3 accesses on `ptr`
struct Struct_2_t {
    char _pad_start[8];
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
    __int64 field_18; // offset 24
};

// inferred from 3 accesses on `ptr2`
struct Struct_3_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
};

__int64 sub_14002DAE0();
__int64 sub_1400F3600();
__int64 sub_14002DB45();
extern __int64 off_1401139B0;
extern __int64 off_140113998;

__int64 __fastcall sub_14002D9A0(struct Struct_1_t *a1, size_t *a2, size_t a3, size_t a4) {
    struct Struct_3_t *ptr2;
    struct Struct_2_t *ptr;
    __int64 v9;
    __int64 v5;
    __int64 i;
    __int64 *src;
    __int64 v2;
    __int64 *result;
    __int64 v7;
    __int64 v10;

    ptr2 = (struct Struct_3_t *)a2;
    ptr = (struct Struct_2_t *)a1;
    sub_14002DAE0(a2);
    v9 = ptr2->field_8;
    if (result > v9) {
        a4 = &off_1401139B0;
        sub_1400F3600(result, v9, v9, a4);
    } else {
        v5 = ptr2->field_0;
        a1 = v5 + result;
        i = (__int64)result;
        i -= v9;
        if ((i != 0)) {
            a4 = ptr2->field_10;
            ++i;
            src = v9 + v5;
            --src;
            a3 = 0;
            if (a4 >= 3) {
                v2 = *src;
                while (v2 != 47) {
                    if (v2 != 92) {
                        ++i;
                        --src;
                        v9 -= (__int64)result;
                        if ((v9 == 0)) {
                            result = 10;
                        } else {
                            if (v9 == 2) {
                                result = a1->field_0;
                                a4 = a1->field_1;
                                result = (__int64 *)((__int64)(__int64)result ^ 46);
                                a4 ^= 46;
                                a4 |= (__int64)result;
                                result = (a4 == 0) ? 1 : 0;
                                result = (__int64 *)((__int64)(__int64)result ^ 9);
                            } else {
                                result = 9;
                                if (v9 == 1) {
                                    if (a1->field_0 == 46) {
                                        result = 0;
                                        result = (a4 >= 3) ? 1 : 0;
                                        result += (__int64)(__int64)result*2;
                                        result += 7;
                                    }
                                }
                            }
                        }
                        a3 += v9;
                        *(__int64 *)ptr = (__int64)(a3);
                        ptr->field_8 = result;
                        ptr->field_10 = a1;
                        ptr->field_18 = v9;
                        return a3;
                    }
                }
            } else {
                while (*src != 92) {
                    ++i;
                    --src;
                    return (__int64)src;
                }
            }
            i = -i;
            result += i;
            ++result;
            if (result > v9) {
                v2 = &off_140113998;
                sub_1400F3600(result, v9, v9, v2);
                a3 = *(result + 56);
                if (a3 > 1) JUMPOUT(0x14002db2f);
                result = ((__int64 *)a1)[7];
                if (result != 0) JUMPOUT(0x14002db85);
                a2 = ((__int64 *)a1)[2];
                a4 = v9 - 5;
                if (a4 > 1) JUMPOUT(0x14002db85);
                v5 = (a2 == 6) ? 1 : 0;
                v7 = a1->field_0;
                v10 = a1->field_8;
                i = (a3 != 0) ? 1 : 0;
                i |= v5;
                if ((i == 0)) JUMPOUT(0x14002db35);
                v5 = 0;
                return sub_14002DB45();
            } else {
                v5 += (__int64)result;
                a3 = 1;
                a1 = (struct Struct_1_t *)v5;
            }
        } else {
            a4 = ptr2->field_10;
            a3 = 0;
        }
        return a3;
    }
    return (__int64)result;
}