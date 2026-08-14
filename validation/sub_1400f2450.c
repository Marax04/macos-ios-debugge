// inferred from 3 accesses on `ptr`
struct Struct_1_t {
    __int64 field_0; // offset 0
    char _pad_0[16];
    __int64 field_18; // offset 24
    __int64 field_20; // offset 32
};

__int64 sub_1400F2814();
__int64 sub_1400F281A();
__int64 sub_1400F28A4();
__int64 sub_1400F24E8();
extern __int64 off_1400F2460;
extern __int64 off_140108008;
extern __int64 off_1401253E0;

__int64 __fastcall sub_1400F2450() {
    int v_30;
    int v_8;
    __int64 *src;
    struct Struct_1_t *ptr;
    __int64 *src2;
    __int64 v4;
    __int64 *result;
    __int64 v7;
    __int64 v8;
    __int64 v9;
    __int64 v10;
    __int64 v2;

    src = &off_1400F2460;
    JUMPOUT(off_140108008);
    v_8 = v2;
    ptr = *src;
    src2 = src;
    if (ptr->field_0 == 0xE06D7363) {
        if (ptr->field_18 == 4) {
            v4 = ptr->field_20;
            result = v4 - 0x19930520;
            if (result > 2) {
                if (v4 != 0x1994000) {
                    v7 = v_30;
                    result = 0;
                    return (__int64)result;
                }
            }
            sub_1400F2814(src, v4);
            *result = ptr;
            v8 = *(src2 + 8);
            sub_1400F281A();
            *result = v8;
            sub_1400F28A4();
            v_8 = v8;
            v9 = &off_1401253E0;
            v10 = &off_1401253E0;
            return sub_1400F24E8();
        }
    }
    return (__int64)result;
}