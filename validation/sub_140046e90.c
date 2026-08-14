// inferred from 4 accesses on `ptr`
struct Struct_1_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
    __int64 field_18; // offset 24
};

__int64 sub_140046740();
__int64 sub_140046D30();
__int64 off_140108030();
extern __int64 off_140108038;

__int64 __fastcall sub_140046E90(size_t *a1, __int64 a2) {
    __int64 *src;
    struct Struct_1_t *ptr;
    __int64 v7;
    __int64 v4;
    __int64 result;
    __int64 v2;
    __int64 v10;
    __int64 v8;
    __int64 v5;
    __int64 v9;

    src = *a1;
    ptr = a1[2];
    v7 = ptr + (__int64)(__int64)ptr*2;
    ptr = (struct Struct_1_t *)((__int64)(__int64)ptr << 5);
    ptr = (struct Struct_1_t *)((__int64)ptr + (__int64)src);
    if (*(src + v7*8 + 360) != 0) {
        src += v7*8;
        src += 360;
        v4 = *(src + 8);
        off_140108030(v7);
        ((__int64 (*)())off_140108038)(src, 0, v4);
    }
    result = ptr->field_0;
    a1 = src - 1;
    if (a1 >= 4) {
        if (result != 0) {
            if (result == 5) {
                v2 = ptr->field_18;
                if (v2 != 0) {
                    v10 = ptr->field_10;
                    do {
                        sub_140046740(v10);
                        v10 += 32;
                        --v2;
                    } while ((v2 != 0));
                }
                if (ptr->field_8 == 0) {
                    return v2;
                } else {
                    ptr = ptr->field_10;
                    off_140108030();
                    v8 = (__int64)src;
                    a2 = 0;
                    v5 = (__int64)ptr;
                    JUMPOUT(off_140108038);
                }
            }
            ptr += 8;
            v9 = (__int64)ptr;
            return sub_140046D30();
        }
        return v9;
    }
    return result;
}