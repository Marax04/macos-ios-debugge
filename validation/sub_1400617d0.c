// inferred from 4 accesses on `ptr`
struct Struct_1_t {
    char _pad_start[8];
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
    char _pad_10[8];
    __int64 field_20; // offset 32
    __int64 field_28; // offset 40
};

__int64 sub_1400F27F0();
__int64 off_140108030();
__int64 off_140108038();
extern __int64 off_1401222D4;
extern __int64 off_14011E6E0;

__int64 __fastcall sub_1400617D0(int a1, __int64 *a2, int a3, __int64 a4) {
    struct Struct_1_t *ptr;
    __int64 v4;
    __int64 v8;
    __int64 *src;
    __int64 v7;
    __int64 v2;
    __int64 v5;
    __int64 v6;

    ptr = (struct Struct_1_t *)a2;
    v4 = a1;
    v8 = *a2;
    src = v8 - 2;
    if (v8 >= 2) a1 = src;
    src = &off_1401222D4;
    v7 = 0x8000000000000003;
    if (a1) {
        src = ptr->field_8;
        if (src != v7) {
            if (src > 0) {
                v2 = ptr->field_10;
                v5 = a4;
                v6 = a3;
                off_140108030(6);
                off_140108038(src, 0, v2);
            }
        }
        src = 0x8000000000000002;
        ptr->field_8 = src;
        src = 24;
    } else {
        src = ptr->field_20;
        if (src != v7) {
            if (src > 0) {
                v2 = ptr->field_28;
                v5 = a4;
                v6 = a3;
                off_140108030(v4, ptr, 176);
                off_140108038(src, 0, v2);
                a3 = v6;
                a4 = v5;
            }
        }
        src = 0x8000000000000002;
        ptr->field_20 = src;
        src = 48;
        a1 = 40;
    }
    *(__int64 *)(ptr + a1) = (__int64)(a3);
    *(__int64 *)((__int64)ptr + (__int64)src) = a4;
    v5 = 120;
    if (v8 >= 2) {
        src = &off_14011E6E0;
        v5 = *(src + v8*8 - 16);
    }
    src = *(__int64 *)(ptr + v5);
    if (src != v7) {
        if (src > 0) {
            v2 = *(__int64 *)(ptr + v5 + 8);
            off_140108030(16, a2, v6, v5);
            off_140108038(src, 0, v2);
        }
    }
    src = *(__int64 *)(ptr + v5 + 24);
    if (src != v7) {
        if (src > 0) {
            v2 = *(__int64 *)(ptr + v5 + 32);
            off_140108030();
            off_140108038(src, 0, v2);
        }
    }
    src = 0x8000000000000000;
    *(__int64 *)(ptr + v5) = (__int64)(src);
    *(__int64 *)(ptr + v5 + 16) = (__int64)(1);
    *(__int64 *)(ptr + v5 + 24) = (__int64)(src);
    return sub_1400F27F0();
}