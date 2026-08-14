// inferred from 2 accesses on `a1`
struct Struct_1_t {
    char field_0; // offset 0
    __int64 field_1; // offset 1
};

__int64 sub_140026B92();
extern __int64 off_140121218;
extern __int64 off_140013550;
extern __int64 off_140110F78;

__int64 __fastcall sub_1400269E0(struct Struct_1_t *a1) {
    __int64 v_28;
    int v_30;
    char *str;
    __int64 v1;
    __int64 *src;
    __int64 v2;
    __int64 v3;

    v1 = a1->field_0;
    src = &off_140121218;
    v1 = *(src + v1*4);
    v1 += (__int64)src;
    JUMPOUT(v1);
    v1 = a1->field_1;
    str = (char *)v1;
    v_28 = (__int64)str;
    v2 = &off_140013550;
    v_30 = v2;
    v3 = &off_140110F78;
    return sub_140026B92();
}