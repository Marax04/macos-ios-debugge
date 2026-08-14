// inferred from 2 accesses on `ptr`
struct Struct_1_t {
    char _pad_start[8];
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
};

__int64 sub_1400F7BC0();
__int64 off_140108030();
__int64 off_140108038();
extern __int64 off_140114FC8;

__int64 __fastcall sub_1400F7CF0(__int64 a1, __int64 str) {
    int v_38;
    int v_40;
    char *str2;
    __int64 *v4;
    __int64 v3;
    __int64 result;
    __int64 v5;
    struct Struct_1_t *ptr;

    v4 = (__int64 *)ptr;
    v3 = ptr->field_8;
    result = ptr->field_10;
    v_38 = v3;
    v_40 = result;
    str = 5;
    v5 = &off_140114FC8;
    sub_1400F7BC0(a1, str, str2, v5);
    if (*v4 != 0) {
        off_140108030();
        off_140108038(a1, 0, v3);
    }
    return result;
}