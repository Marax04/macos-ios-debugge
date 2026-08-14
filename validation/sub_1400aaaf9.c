__int64 sub_1400B0C90();
__int64 sub_1400A8DAD();
extern __int64 off_140108030;
extern __int64 off_140108038;

__int64 __fastcall sub_1400AAAF9(__int64 str, __int64 a2) {
    int v_150;
    int v_178;
    int v_c0;
    __int64 v3;
    __int64 v4;
    __int64 v1;

    if (!((0 /* unresolved: flags == */))) {
        v3 = off_140108030;
        ((__int64 (*)())v3)();
        v4 = off_140108038;
        ((__int64 (*)())v4)(v1, 0, v_178);
        ((__int64 (*)())v3)();
        ((__int64 (*)())v4)(v1, 0, v_150);
    }
    sub_1400B0C90(str);
    if (v_c0 != 0) JUMPOUT(0x1400a8d97);
    return sub_1400A8DAD();
}