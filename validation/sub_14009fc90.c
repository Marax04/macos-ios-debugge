__int64 sub_14009FD7B();
extern __int64 off_140124954;
extern __int64 off_140119C37;
extern __int64 off_140119DA6;
extern __int64 off_14009FE70;
extern __int64 off_140119CF0;

__int64 __fastcall sub_14009FC90(__int64 *a1, __int64 a2, int *a3) {
    __int64 v_28;
    int v_30;
    char *str;
    __int64 v3;
    __int64 *src;
    __int64 v1;
    __int64 v5;
    __int64 v2;
    __int64 v6;
    __int64 v7;
    __int64 v8;

    v3 = a2;
    a2 = *a1;
    a1 += 2;
    src = &off_140124954;
    a2 = *(src + a2*4);
    a2 += (__int64)src;
    JUMPOUT(a2);
    v1 = a3[3];
    a2 = &off_140119C37;
    a3 = 17;
    v5 = v3;
    JUMPOUT(v1);
    v2 = a3[3];
    a2 = &off_140119DA6;
    a3 = 23;
    v6 = v3;
    JUMPOUT(v2);
    str = (char *)v6;
    v_28 = (__int64)str;
    v7 = &off_14009FE70;
    v_30 = v7;
    v8 = &off_140119CF0;
    return sub_14009FD7B();
}