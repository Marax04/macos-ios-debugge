// inferred from 3 accesses on `ptr`
struct Struct_1_t {
    char _pad_start[24];
    __int64 field_18; // offset 24
    char _pad_18[16];
    __int64 field_30; // offset 48
    __int64 field_38; // offset 56
};

// inferred from 3 accesses on `ptr2`
struct Struct_2_t {
    char _pad_start[8];
    __int64 field_8; // offset 8
    char _pad_8[16];
    __int64 field_20; // offset 32
    __int64 field_28; // offset 40
};

// inferred from 2 accesses on `i`
struct Struct_3_t {
    char _pad_start[32];
    __int64 field_20; // offset 32
    __int64 field_28; // offset 40
};

// inferred from 3 accesses on `ptr3`
struct Struct_4_t {
    char _pad_start[24];
    __int64 field_18; // offset 24
    char _pad_18[24];
    __int64 field_38; // offset 56
    __int64 field_40; // offset 64
};

__int64 sub_1400B1679();
extern __int64 off_140108030;
extern __int64 off_140108038;

__int64 __fastcall sub_1400B1470(__int64 *a1, __int64 a2) {
    int v_20;
    int v_28;
    __int64 v_30;
    int v_38;
    __int64 v_40;
    __int64 v_48;
    int v_50;
    struct Struct_2_t *ptr2;
    struct Struct_3_t *i;
    __int64 result;
    __int64 v12;
    __int64 *src;
    struct Struct_1_t *ptr;
    struct Struct_4_t *ptr3;
    __int64 v11;
    __int64 v6;
    __int64 i2;
    __int64 *v8;

    ptr2 = (struct Struct_2_t *)a1;
    if (*a1 != 0) {
        i = ptr2->field_8;
        ((__int64 (*)())off_140108030)();
        ((__int64 (*)())off_140108038)(result, 0, i);
    }
    result = ptr2->field_20;
    v_20 = result;
    v_30 = (__int64)ptr2;
    result = ptr2->field_28;
    v_38 = result;
    if (result != 0) {
        i = 0;
        v12 = off_140108030;
        ptr2 = off_140108038;
        do {
            v_48 = (__int64)i;
            result = i + (__int64)(__int64)i*4;
            result <<= 4;
            a1 = (__int64 *)v_20;
            i = a1 + result;
            src = i->field_20;
            v_40 = (__int64)i;
            result = i->field_28;
            v_50 = result;
            if (result == 0) {
                ptr = (struct Struct_1_t *)v_40;
                if (ptr->field_18 == 0) {
                    i = (struct Struct_3_t *)v_48;
                    if (ptr->field_30 == 0) {
                        ++i;
                        ptr3 = (struct Struct_4_t *)v_30;
                        if (ptr3->field_18 != 0) {
                            ((__int64 (*)())off_140108030)();
                            ((__int64 (*)())off_140108038)(result, 0, v_20);
                        }
                        i = ptr3->field_38;
                        ptr2 = ptr3->field_40;
                        if (ptr2 == 0) JUMPOUT(0x1400b1693);
                        ptr = i + 8;
                        v11 = off_140108030;
                        v6 = off_140108038;
                        return sub_1400B1679();
                    }
                    src = ptr->field_38;
                    ((__int64 (*)())v12)();
                    ((__int64 (*)())ptr2)(result, 0, src);
                    return (__int64)src;
                }
                ((__int64 (*)())v12)();
                ((__int64 (*)())ptr2)(result, 0, src);
                return (__int64)src;
            }
            i2 = 0;
            do {
                v8 = (__int64 *)i2;
                v8 = (__int64 *)((__int64)(__int64)v8 << 5);
                result = *(__int64 *)((__int64)src + (__int64)v8 + 8);
                v_28 = result;
                i = *(__int64 *)((__int64)src + (__int64)v8 + 16);
                v8 = (__int64 *)((__int64)v8 + (__int64)src);
                if (*v8 == 0) {
                    ++i2;
                    return i2;
                }
                ((__int64 (*)())v12)();
                ((__int64 (*)())ptr2)(result, 0, v_28);
                return i2;
            } while (i2 != v_50);
            return i2;
        } while (i != v_38);
    }
    return result;
}