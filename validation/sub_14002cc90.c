// inferred from 2 accesses on `a2`
struct Struct_1_t {
    char field_0; // offset 0
    __int64 field_1; // offset 1
};

__int64 sub_14002CDBC();

int __fastcall sub_14002CC90(__int64 a1,struct Struct_1_t *a2, int a3, __int64 a4) {
    int v2;
    int v6;
    int v1;
    int v7;
    int v4;
    int v3;
    int v5;

    if (a3 == 0) {
        a4 = 0;
        v2 = 0;
        v6 = 0;
        v1 = 0;
        v7 = 0;
        v4 = 0;
        v3 = 0;
        v5 = 0;
        return sub_14002CDBC();
    } else {
        v5 = a2->field_0;
        v3 = 92;
        if (v5 == 47) v5 = v3;
        if (a3 != 1) {
            v1 = a2->field_1;
            if (v1 != 47) v3 = v1;
            if (a3 != 2) JUMPOUT(0x14002cd0f);
            a4 = 0;
            v2 = 0;
            v6 = 0;
            v1 = 0;
            v7 = 0;
            v4 = 0;
            return sub_14002CDBC();
        } else {
            a4 = 0;
            v2 = 0;
            v6 = 0;
            v1 = 0;
            v7 = 0;
            v4 = 0;
            v3 = 0;
            return sub_14002CDBC();
        }
    }
}