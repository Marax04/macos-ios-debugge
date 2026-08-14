// inferred from 3 accesses on `ptr`
struct Struct_1_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
};

__int64 sub_1400F6DC0();
__int64 off_140108030();
__int64 off_140108038();
extern __int64 off_14012D010;
extern __int64 off_140110260;
extern __int64 off_140110600;
extern __int64 off_14012D180;

__int64 __fastcall sub_1400207F0(size_t a1, __int64 a2) {
    int v_20;
    int v_30;
    char *str;
    char *str2;
    char *str3;
    __int64 result;
    __int64 v6;
    __int64 v9;
    __int64 v5;
    __int64 *src;
    __int64 v2;
    __int64 *src2;
    struct Struct_1_t *ptr;
    __int64 v7;

    str = 0;
    result = off_14012D010;
    if (result != 0) {
        str2 = str;
        str3 = str2;
        v6 = &off_140110260;
        v_20 = v6;
        v9 = &off_14012D010;
        v5 = &off_140110600;
        sub_1400F6DC0(v9, 0, str3, v5);
        a1 = (size_t)str;
        src = (__int64 *)v_30;
        if (a1 == 3) {
            result = (__int64)src;
        } else {
            if (off_14012D180 == 0) JUMPOUT(0x1400208f1);
            result = &off_14012D180;
            if (a1 >= 2) {
                a1 = (size_t)src;
                a1 &= 3;
                if (a1 == 1) {
                    v2 = result;
                    src2 = *(src - 1);
                    ptr = *(src + 7);
                    v7 = ptr->field_0;
                    if (v7 != 0) {
                        ((__int64 (*)())v7)(src2);
                    }
                    --src;
                    if (ptr->field_8 != 0) {
                        if (ptr->field_10 >= 17) {
                            src2 = *(src2 - 8);
                        }
                        off_140108030();
                        off_140108038(v7, 0, src2);
                    }
                    off_140108030();
                    off_140108038(v7, 0, src);
                    result = v2;
                }
            }
        }
        return result;
    } else {
        a1 = (size_t)str;
        src = (__int64 *)v_30;
        if (a1 != 3) {
            return (__int64)src;
        } else {
            return (__int64)src;
        }
        return (__int64)src;
    }
    return result;
}