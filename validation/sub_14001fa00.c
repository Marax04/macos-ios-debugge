// inferred from 3 accesses on `ptr`
struct Struct_1_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
    __int64 field_10; // offset 16
};

__int64 sub_140037480();
__int64 off_140108030();
extern __int64 off_140108038;

__int64 __fastcall sub_14001FA00(int *a1, __int64 a2) {
    __int64 result;
    __int64 *src;
    struct Struct_1_t *ptr;
    __int64 v4;
    __int64 v5;

    result = (__int64)a1;
    result &= 3;
    if (result == 1) {
        src = *(a1 - 1);
        ptr = *(a1 + 7);
        result = ptr->field_0;
        if (result != 0) {
            v4 = (__int64)a1;
            ((__int64 (*)())result)(src);
            a1 = (int *)v4;
        }
        --a1;
        v5 = (__int64)a1;
        if (ptr->field_8 != 0) {
            if (ptr->field_10 >= 17) {
                src = *(src - 8);
            }
            off_140108030(a1);
            ((__int64 (*)())off_140108038)(result, 0, src);
        }
        off_140108030();
        JUMPOUT(off_140108038);
        return sub_140037480(result, 0, v5);
    } else {
        return result;
    }
}