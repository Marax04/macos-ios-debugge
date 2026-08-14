// inferred from 2 accesses on `a2`
struct Struct_1_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
};

__int64 sub_1400BDA32();
extern __int64 off_1401249CC;
extern __int64 off_14011D9B8;
extern __int64 off_14011DA45;
extern __int64 off_14011DA28;
extern __int64 off_14011DA37;
extern __int64 off_14011DAA0;
extern __int64 off_14008FE80;
extern __int64 off_14011D9E8;
extern __int64 off_14011D9F8;

__int64 __fastcall sub_1400BD8D0(__int64 *a1,struct Struct_1_t *a2, int a3) {
    __int64 rsp;
    __int64 v_20;
    __int64 v_28;
    __int64 v_30;
    __int64 v_38;
    int v_40;
    __int64 v_58;
    int v_60;
    __int64 *i;
    __int64 *src;

    i = *a1;
    a1 = a2->field_0;
    a2 = a2->field_8;
    a3 = *i;
    src = &off_1401249CC;
    a3 = *(src + a3*4);
    a3 += (__int64)src;
    JUMPOUT(a3);
    i = ((__int64 *)a2)[3];
    a2 = &off_14011D9B8;
    a3 = 26;
    JUMPOUT(i);
    i = ((__int64 *)a2)[3];
    a2 = &off_14011DA45;
    a3 = 14;
    JUMPOUT(i);
    i = ((__int64 *)a2)[3];
    a2 = &off_14011DA28;
    a3 = 15;
    JUMPOUT(i);
    i = ((__int64 *)a2)[3];
    a2 = &off_14011DA37;
    a3 = 14;
    JUMPOUT(i);
    i = ((__int64 *)a2)[3];
    a2 = &off_14011DAA0;
    a3 = 21;
    JUMPOUT(i);
    ++i;
    v_20 = (__int64)i;
    i = rsp + 32;
    v_28 = (__int64)i;
    i = &off_14008FE80;
    v_30 = (__int64)i;
    i = &off_14011D9E8;
    v_38 = (__int64)i;
    v_40 = 1;
    i = &off_14011D9F8;
    v_58 = (__int64)i;
    v_60 = 1;
    return sub_1400BDA32();
}