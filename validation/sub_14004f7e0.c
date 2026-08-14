// inferred from 5 accesses on `ptr`
struct Struct_1_t {
    char _pad_start[8];
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
    __int64 field_18; // offset 24
    __int64 field_20; // offset 32
    __int64 field_28; // offset 40
};

__int64 sub_140046190();
__int64 off_140108030();
extern __int64 off_140108038;

__int64 __fastcall sub_14004F7E0(int *a1, __int64 a2) {
    struct Struct_1_t *ptr;
    __int64 result;
    __int64 v8;
    __int64 v11;
    __int64 v7;
    __int64 v4;
    __int64 v6;
    __int64 v9;
    __int64 v5;
    __int64 v10;
    __int64 v2;

    ptr = (struct Struct_1_t *)a1;
    result = *a1;
    a2 = 0x8000000000000001;
    a2 += result;
    v8 = result;
    v8 >>= 63;
    v8 &= a2;
    if ((v8 == 0)) {
        if (result != 0) {
            v11 = ptr->field_8;
            off_140108030();
            ((__int64 (*)())off_140108038)(result, 0, v11);
        }
        v7 = ptr->field_18;
        result = v7;
        result = -result;
        if (!((0 /* overflow check on (-result) */))) {
            v4 = ptr->field_20;
            v6 = ptr->field_28;
            if (v6 != 0) {
                ptr = (struct Struct_1_t *)v4;
                do {
                    sub_140046190(ptr);
                    ptr += 144;
                    --v6;
                } while ((v6 != 0));
            }
            if (v7 != 0) {
                off_140108030();
                v9 = result;
                a2 = 0;
                v5 = v4;
                JUMPOUT(off_140108038);
            }
        }
    } else {
        if (v8 == 1) {
            v4 = ptr->field_10;
            v10 = ptr->field_18;
            if (v10 != 0) {
                v2 = v4;
                do {
                    sub_140046190(v2, a2);
                    v2 += 144;
                    --v10;
                } while ((v10 != 0));
            }
            if (ptr->field_8 != 0) {
                return v10;
            } else {
            }
        }
    }
    return result;
}