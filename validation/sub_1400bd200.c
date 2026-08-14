// inferred from 2 accesses on `a2`
struct Struct_1_t {
    __int64 field_0; // offset 0
    __int64 field_8; // offset 8
};

__int64 sub_140011760();
extern __int64 off_14008D400;
extern __int64 off_14011B1D8;
extern __int64 off_1400BD380;
extern __int64 off_14011B1F0;
extern __int64 off_1400BD4D0;
extern __int64 off_14011B0D8;
extern __int64 off_14011B108;
extern __int64 off_1400BD5A0;
extern __int64 off_14011B208;
extern __int64 off_1400BD630;
extern __int64 off_14011B220;

__int64 __fastcall sub_1400BD200(__int64 *a1,struct Struct_1_t *a2) {
    __int64 rsp;
    int v_20;
    int v_28;
    int v_30;
    int v_40;
    int v_48;
    int v_50;
    int v_58;
    char *str;
    __int64 v1;
    int v2;

    v1 = *a1;
    v2 = v1 - 5;
    if (v2 >= 1) v1 = v2;
    switch (v1) {
        case 0:
            a1 += 4;
            v_20 = (int)a1;
            v1 = rsp + 32;
            v_28 = v1;
            v1 = &off_14008D400;
            v_30 = v1;
            v1 = &off_14011B1D8;
            break;
        case 1:
            v_20 = (int)a1;
            v1 = rsp + 32;
            v_28 = v1;
            v1 = &off_1400BD380;
            v_30 = v1;
            v1 = &off_14011B1F0;
            break;
        case 2:
            a1 += 4;
            v_20 = (int)a1;
            v1 = rsp + 32;
            v_28 = v1;
            v1 = &off_1400BD4D0;
            v_30 = v1;
            v1 = &off_14011B0D8;
            break;
        case 3:
            a1 += 4;
            v_20 = (int)a1;
            v1 = rsp + 32;
            v_28 = v1;
            v1 = &off_14008D400;
            v_30 = v1;
            v1 = &off_14011B108;
            break;
        case 4:
            a1 += 4;
            v_20 = (int)a1;
            v1 = rsp + 32;
            v_28 = v1;
            v1 = &off_1400BD5A0;
            v_30 = v1;
            v1 = &off_14011B208;
            break;
        case 5:
            a1 += 4;
            v_20 = (int)a1;
            v1 = rsp + 32;
            v_28 = v1;
            v1 = &off_1400BD630;
            v_30 = v1;
            v1 = &off_14011B220;
            break;
    }
    str = (char *)v1;
    v_40 = 1;
    v_58 = 0;
    v1 = rsp + 40;
    v_48 = v1;
    v_50 = 1;
    a1 = a2->field_0;
    a2 = a2->field_8;
    return sub_140011760(a1, a2, str);
}