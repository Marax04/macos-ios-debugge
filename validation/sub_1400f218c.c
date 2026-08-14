// inferred from 4 accesses on `ptr`
struct Struct_1_t {
    int field_0; // offset 0
    char _pad_0[2];
    __int64 field_6; // offset 6
    char _pad_6[6];
    int field_14; // offset 20
    __int64 field_18; // offset 24
};

// inferred from 3 accesses on `ptr2`
struct Struct_2_t {
    char _pad_start[8];
    int field_8; // offset 8
    __int64 field_C; // offset 12
    char _pad_C[16];
    __int64 field_24; // offset 36
};

__int64 sub_1400F221F();
extern __int64 off_140000000;
extern __int64 off_14000003C;

__int64 __fastcall sub_1400F218C(int a1) {
    __int64 rsp;
    __int64 v6;
    __int64 result;
    struct Struct_1_t *ptr;
    struct Struct_2_t *ptr2;
    int v3;
    __int64 v4;
    __int64 v7;

    v6 = a1;
    result = 0x5A4D;
    if (off_140000000 == result) {
        ptr = off_14000003C;
        ptr2 = &off_140000000;
        ptr = (struct Struct_1_t *)((__int64)ptr + (__int64)ptr2);
        if (ptr->field_0 == 0x4550) {
            result = 523;
            if (ptr->field_18 == result) {
                v6 -= (__int64)ptr2;
                v3 = ptr->field_14;
                ptr2 += 24;
                ptr2 = (struct Struct_2_t *)((__int64)ptr2 + (__int64)ptr);
                result = ptr->field_6;
                v4 = result + result*4;
                v7 = ptr2 + v4*8;
                *(__int64 *)rsp = ptr2;
                while (ptr2 != v7) {
                    a1 = ptr2->field_C;
                    if (v6 < v4) {
                        ptr2 += 40;
                    }
                    result = ptr2->field_8;
                    result += a1;
                    if (v6 >= result) {
                        return result;
                    }
                    if (ptr2 != 0) {
                        if (ptr2->field_24 >= 0) {
                            result = 1;
                            return sub_1400F221F();
                        } else {
                            result = 0;
                            return sub_1400F221F();
                        }
                    } else {
                        result = 0;
                        return sub_1400F221F();
                    }
                }
                v3 = 0;
                return result;
            }
        }
    }
    result = 0;
    return sub_1400F221F();
}