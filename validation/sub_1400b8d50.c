// inferred from 2 accesses on `a1`
struct Struct_1_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
};

// inferred from 5 accesses on `ptr`
struct Struct_2_t {
    char _pad_start[8];
    __int64 field_8; // offset 8
    char _pad_8[8];
    __int64 field_18; // offset 24
    __int64 field_20; // offset 32
    char _pad_20[8];
    __int64 field_30; // offset 48
    char _pad_30[16];
    __int64 field_48; // offset 72
};

__int64 off_140108030();
extern __int64 off_140108038;

__int64 __fastcall sub_1400B8D50(struct Struct_1_t *a1, __int64 a2) {
    __int64 v2;
    __int64 v3;
    __int64 *src;
    __int64 *v5;
    __int64 v9;
    struct Struct_2_t *ptr;
    __int64 v7;
    __int64 v8;
    __int64 v6;
    __int64 result;

    v2 = a1->field_0;
    v2 <<= 1;
    if (v2 != 0) {
        v3 = a1->field_8;
        src = (__int64 *)a1;
        off_140108030();
        ((__int64 (*)())off_140108038)(v2, 0, v3);
        v5 = *(src + 24);
        v5 = (__int64 *)((__int64)(__int64)v5 << 1);
        if (v5 != 0) {
            v9 = ((__int64 *)a1)[4];
            off_140108030(src);
            JUMPOUT(off_140108038);
            ptr = (struct Struct_2_t *)v5;
            if (*v5 != 0) {
                v7 = ptr->field_8;
                off_140108030(v5, 0, ptr);
                ((__int64 (*)())off_140108038)(v5, 0, v7);
            }
            if (ptr->field_18 != 0) {
                v8 = ptr->field_20;
                off_140108030();
                ((__int64 (*)())off_140108038)(v5, 0, v8);
            }
            v6 = ptr->field_30;
            v6 <<= 1;
            if (v6 != 0) JUMPOUT(0x1400b8e25);
            result = ptr->field_48;
            result <<= 1;
            if (result != 0) JUMPOUT(0x1400b8e49);
            return result;
        }
    } else {
        v5 = ((__int64 *)a1)[3];
        v5 = (__int64 *)((__int64)(__int64)v5 << 1);
        if (v5 != 0) {
            return (__int64)v5;
        }
    }
    return result;
}