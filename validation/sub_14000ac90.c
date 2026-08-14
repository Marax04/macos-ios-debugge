// inferred from 3 accesses on `ptr`
struct Struct_1_t {
    char _pad_start[1];
    char field_1; // offset 1
    char field_2; // offset 2
    __int64 field_3; // offset 3
};

__int64 sub_14000AEFE();
__int64 sub_14000AE19();
extern __int64 off_14011B24D;

__int64 __fastcall sub_14000AC90(__int64 a1, int a2) {
    __int64 v3;
    __int64 v4;
    __int64 *src;
    __int64 v6;
    struct Struct_1_t *ptr;
    __int64 v8;
    __int64 *src2;
    __int64 v1;

    v3 = a1;
    v4 = a1 + a2;
    if (a2 == 0) {
        a2 = 0;
        src = (__int64 *)v3;
        a1 = 0;
    } else {
        v6 = &off_14011B24D;
        a2 = 0;
        src = (__int64 *)v3;
        do {
            ptr = (struct Struct_1_t *)src;
            v8 = a2;
            src = *src;
            src2 = src;
            a2 = (int)src2;
            a2 &= 31;
            v3 = ptr->field_1;
            v3 &= 63;
            if (src2 <= 223) {
                src = ptr + 2;
                a2 <<= 6;
                a2 |= v3;
                src2 = (__int64 *)a2;
                a2 = (int)src;
                a2 -= (__int64)ptr;
                a2 += v8;
                ptr = src2 - 9;
                if (ptr < 5) {
                    a1 = 0;
                    a2 = 0;
                    return sub_14000AEFE();
                }
                if (src2 == 32) {
                    return a2;
                }
                if (src2 >= 128) {
                    ptr = (struct Struct_1_t *)src2;
                    ptr = (struct Struct_1_t *)((__int64)(__int64)ptr >> 8);
                    if (ptr > 31) {
                        if (ptr == 32) {
                            src2 = *(src2 + v6);
                            src2 = (__int64 *)((__int64)(__int64)src2 >> 1);
                            if (((__int64)src2 & 1) != 0) {
                                return (__int64)src2;
                            }
                            if (src == v4) JUMPOUT(0x14000aefe);
                            v1 = &off_14011B24D;
                            return sub_14000AE19();
                        }
                        if (ptr == 48) {
                            src2 = (src2 == 0x3000) ? 1 : 0;
                            return (__int64)src2;
                        }
                        return (__int64)src2;
                    }
                    if (ptr == 0) {
                        src2 = *(src2 + v6);
                        return (__int64)src2;
                    }
                    if (ptr == 22) {
                        src2 = (src2 == 0x1680) ? 1 : 0;
                        return (__int64)src2;
                    }
                }
                return (__int64)src2;
            }
            src2 = ptr->field_2;
            v3 <<= 6;
            src2 = (__int64 *)((__int64)(__int64)src2 & 63);
            src2 = (__int64 *)((__int64)(__int64)src2 | v3);
            if (src < 240) {
                src = ptr + 3;
                a2 <<= 12;
                src2 = (__int64 *)((__int64)(__int64)src2 | a2);
                return (__int64)src2;
            }
            src = ptr + 4;
            v3 = ptr->field_3;
            a2 &= 7;
            a2 <<= 18;
            src2 = (__int64 *)((__int64)(__int64)src2 << 6);
            v3 &= 63;
            v3 |= (__int64)src2;
            v3 |= a2;
            src2 = (__int64 *)v3;
            return (__int64)src2;
        } while (src != v4);
        return (__int64)src2;
    }
    return (__int64)src2;
}