// inferred from 2 accesses on `ptr`
struct Struct_1_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
};

__int64 sub_1400A7631();

__int64 __fastcall sub_1400A752C() {
    int v_10;
    int v_268;
    int v_270;
    int v_438;
    int v_440;
    int v_8;
    __int64 i;
    __int64 v13;
    struct Struct_1_t *ptr;
    __int64 v11;
    __int64 v6;
    __int64 v2;
    __int64 v4;
    __int64 v8;
    __int64 v5;
    __int64 v7;
    __int64 *dst;
    __int64 v10;
    __int64 v9;

    *(dst + v10*8 + 8) = 4;
    *(dst + v10*8 + 16) = 0;
    *(dst + v10*8 + 24) = v6;
    *(dst + v10*8 + 32) = v11;
    *(dst + v10*8 + 36) = 0;
    i = v13;
    ++i;
    v13 = i;
    v_270 = i;
    ptr += 16;
    while (ptr != v9) {
        v11 = ptr->field_0;
        v6 = ptr->field_8;
        v2 =  + v13*4;
        v2 += v13;
        if (v13 == 0) JUMPOUT(0x1400a7513);
        i = dst + v2*8;
        i -= 40;
        if (i == 0) JUMPOUT(0x1400a7513);
        i = dst + v2*8;
        v4 = v_8;
        v8 = v_10;
        v8 += v4;
        if (v11 > v8) JUMPOUT(0x1400a7513);
        v6 -= v4;
        v_10 = v6;
    }
    if (v13 == 0) JUMPOUT(0x1400a76eb);
    v6 = v_440;
    v5 = v_268;
    if (v6 == 0) JUMPOUT(0x1400abc79);
    v7 = v_438;
    v6 <<= 4;
    v6 += v7;
    i = v7 + 16;
    return sub_1400A7631();
}