/*************************************************************************************
* qTESLA: an efficient post-quantum signature scheme based on the R-LWE problem
*
* Abstract: CDT constants for the Gaussian sampler
**************************************************************************************/

#ifndef CDTSAMP
#define CDTSAMP

#include <stdint.h>
#include "params.h"


// Sigma = 22.93, 64-bit precision

#define CDT_ROWS 209
#define CDT_COLS 1
#define CDT_SIZE CDT_ROWS 

static const int64_t cdt_v[CDT_ROWS*CDT_COLS] = {
    0x0000000000000000LL, // 0
    0x023A1B3F94933202LL, // 1
    0x06AD3C4C19410B24LL, // 2
    0x0B1D1E95803CBB73LL, // 3
    0x0F879D85E7AB7F6FLL, // 4
    0x13EA9C5C52732915LL, // 5
    0x18440933FFD2011BLL, // 6
    0x1C91DFF191E15D07LL, // 7
    0x20D22D0F2017900DLL, // 8
    0x25031040C1E626EFLL, // 9
    0x2922BEEBA163019DLL, // 10
    0x2D2F866A3C5122D3LL, // 11
    0x3127CE192059EF64LL, // 12
    0x350A1928231CB01ALL, // 13
    0x38D5082CD4FCC414LL, // 14
    0x3C875A73B33ADA6BLL, // 15
    0x401FEF0E67CD47D3LL, // 16
    0x439DC59E3077B59CLL, // 17
    0x46FFFEDA4FC0A316LL, // 18
    0x4A45DCD32E9CAA91LL, // 19
    0x4D6EC2F3922E5C24LL, // 20
    0x507A35C1FB354670LL, // 21
    0x5367DA64EA5F1C63LL, // 22
    0x563775ED5B93E26ELL, // 23
    0x58E8EC6B50CB95F8LL, // 24
    0x5B7C3FD0B999197DLL, // 25
    0x5DF18EA7664D810ELL, // 26
    0x6049129F03B5CD6DLL, // 27
    0x62831EF856A48427LL, // 28
    0x64A01ED314BA206FLL, // 29
    0x66A09363CA89DAA3LL, // 30
    0x688512173EF213F5LL, // 31
    0x6A4E42A8B137E138LL, // 32
    0x6BFCDD302C5B888ALL, // 33
    0x6D91A82DF797EAB8LL, // 34
    0x6F0D7697EBA6A51DLL, // 35
    0x707125ED27F05CF1LL, // 36
    0x71BD9C544C184D8DLL, // 37
    0x72F3C6C7FB380322LL, // 38
    0x74149755088E5CC6LL, // 39
    0x7521036D434271D4LL, // 40
    0x761A02516A02B0CELL, // 41
    0x77008B9461817A43LL, // 42
    0x77D595B95BC6A0FELL, // 43
    0x789A14EE338BB727LL, // 44
    0x794EF9E2D7C53213LL, // 45
    0x79F530BE414FE24DLL, // 46
    0x7A8DA03110886732LL, // 47
    0x7B1928A59B3AA79ELL, // 48
    0x7B98A38CE58D06AELL, // 49
    0x7C0CE2C7BAD3164ALL, // 50
    0x7C76B02ADDE64EF2LL, // 51
    0x7CD6CD1D13EE98F2LL, // 52
    0x7D2DF24DA06E2473LL, // 53
    0x7D7CCF81A5CD98B9LL, // 54
    0x7DC40B76C24FB5D4LL, // 55
    0x7E0443D92DE22661LL, // 56
    0x7E3E0D4B91401720LL, // 57
    0x7E71F37EC9C1DE8DLL, // 58
    0x7EA07957CE6B9051LL, // 59
    0x7ECA1921F1AF6404LL, // 60
    0x7EEF44CBC73DA35BLL, // 61
    0x7F10662D0574233DLL, // 62
    0x7F2DDF53CDDCD427LL, // 63
    0x7F480AD7DF028A76LL, // 64
    0x7F5F3C324B0F66B2LL, // 65
    0x7F73C018698C18A7LL, // 66
    0x7F85DCD8D69F8939LL, // 67
    0x7F95D2B96ED3DA10LL, // 68
    0x7FA3DC55532D71BBLL, // 69
    0x7FB02EFA1DDDC61ELL, // 70
    0x7FBAFB038BAE76E4LL, // 71
    0x7FC46C34F918B3E3LL, // 72
    0x7FCCAA102B95464CLL, // 73
    0x7FD3D828F7D49092LL, // 74
    0x7FDA16756C11CF83LL, // 75
    0x7FDF819A3A7BFE69LL, // 76
    0x7FE4333332A5FEBDLL, // 77
    0x7FE84217AA0DE2B3LL, // 78
    0x7FEBC29AC3100A8BLL, // 79
    0x7FEEC6C78F0D514ELL, // 80
    0x7FF15E9914396F2ALL, // 81
    0x7FF3982E4982FB97LL, // 82
    0x7FF57FFA236862D1LL, // 83
    0x7FF720EFD36F4850LL, // 84
    0x7FF884AB61732BC7LL, // 85
    0x7FF9B396CA3B383CLL, // 86
    0x7FFAB50BD1DD3633LL, // 87
    0x7FFB8F72BA84114BLL, // 88
    0x7FFC485E115A3388LL, // 89
    0x7FFCE4A3C3B92B98LL, // 90
    0x7FFD6873AE755E4ALL, // 91
    0x7FFDD76BD840FDA1LL, // 92
    0x7FFE34AA86CE6870LL, // 93
    0x7FFE82DE5CA6A885LL, // 94
    0x7FFEC454ABAA26DFLL, // 95
    0x7FFEFB0625FADB89LL, // 96
    0x7FFF28A214B1160FLL, // 97
    0x7FFF4E983945429DLL, // 98
    0x7FFF6E217C168A6ALL, // 99
    0x7FFF884787F2B986LL, // 100
    0x7FFF9DEB70088602LL, // 101
    0x7FFFAFCB7B419E48LL, // 102
    0x7FFFBE882DABB8F8LL, // 103
    0x7FFFCAA8A65BDA07LL, // 104
    0x7FFFD49E66188754LL, // 105
    0x7FFFDCC891191605LL, // 106
    0x7FFFE376BC4B0583LL, // 107
    0x7FFFE8EB54D33209LL, // 108
    0x7FFFED5DAEE78F4ELL, // 109
    0x7FFFF0FBC7A6933DLL, // 110
    0x7FFFF3EBC43A9213LL, // 111
    0x7FFFF64D375FC4CCLL, // 112
    0x7FFFF83A354A0431LL, // 113
    0x7FFFF9C83CE9BB0DLL, // 114
    0x7FFFFB08FCAC61A6LL, // 115
    0x7FFFFC0AF80A1A6FLL, // 116
    0x7FFFFCDA127DDE76LL, // 117
    0x7FFFFD8003E62E56LL, // 118
    0x7FFFFE04B9BF9C5BLL, // 119
    0x7FFFFE6EA82EF9BDLL, // 120
    0x7FFFFEC30D64CD46LL, // 121
    0x7FFFFF0629856684LL, // 122
    0x7FFFFF3B6CEEE3F1LL, // 123
    0x7FFFFF659E6F7BA6LL, // 124
    0x7FFFFF86FAC1036ALL, // 125
    0x7FFFFFA14E69EDE9LL, // 126
    0x7FFFFFB60AF6ACB7LL, // 127
    0x7FFFFFC65857AECFLL, // 128
    0x7FFFFFD3230F314FLL, // 129
    0x7FFFFFDD27BE0A17LL, // 130
    0x7FFFFFE4FC86CDFFLL, // 131
    0x7FFFFFEB18AA9E4CLL, // 132
    0x7FFFFFEFDAB1FD73LL, // 133
    0x7FFFFFF38D65D499LL, // 134
    0x7FFFFFF66BD0EB8CLL, // 135
    0x7FFFFFF8A4782371LL, // 136
    0x7FFFFFFA5BEF7C27LL, // 137
    0x7FFFFFFBAEEB0B4CLL, // 138
    0x7FFFFFFCB3E55903LL, // 139
    0x7FFFFFFD7C6FE192LL, // 140
    0x7FFFFFFE163E99E3LL, // 141
    0x7FFFFFFE8BFC2558LL, // 142
    0x7FFFFFFEE5F1CE80LL, // 143
    0x7FFFFFFF2A8C31FDLL, // 144
    0x7FFFFFFF5EC3CD18LL, // 145
    0x7FFFFFFF866F376BLL, // 146
    0x7FFFFFFFA483A906LL, // 147
    0x7FFFFFFFBB4780C4LL, // 148
    0x7FFFFFFFCC79BEB2LL, // 149
    0x7FFFFFFFD970CBE1LL, // 150
    0x7FFFFFFFE3326D21LL, // 151
    0x7FFFFFFFEA865AB8LL, // 152
    0x7FFFFFFFF004A7C8LL, // 153
    0x7FFFFFFFF420E4F9LL, // 154
    0x7FFFFFFFF732B791LL, // 155
    0x7FFFFFFFF97C764FLL, // 156
    0x7FFFFFFFFB303DDDLL, // 157
    0x7FFFFFFFFC73D5A3LL, // 158
    0x7FFFFFFFFD63AA57LL, // 159
    0x7FFFFFFFFE15140DLL, // 160
    0x7FFFFFFFFE981196LL, // 161
    0x7FFFFFFFFEF89992LL, // 162
    0x7FFFFFFFFF3F9A0CLL, // 163
    0x7FFFFFFFFF73BA0BLL, // 164
    0x7FFFFFFFFF99EBBBLL, // 165
    0x7FFFFFFFFFB5DAA0LL, // 166
    0x7FFFFFFFFFCA3E7BLL, // 167
    0x7FFFFFFFFFD91985LL, // 168
    0x7FFFFFFFFFE3E70ALL, // 169
    0x7FFFFFFFFFEBBE45LL, // 170
    0x7FFFFFFFFFF16C5CLL, // 171
    0x7FFFFFFFFFF587BELL, // 172
    0x7FFFFFFFFFF87E7FLL, // 173
    0x7FFFFFFFFFFAA108LL, // 174
    0x7FFFFFFFFFFC29F5LL, // 175
    0x7FFFFFFFFFFD43E8LL, // 176
    0x7FFFFFFFFFFE0DD7LL, // 177
    0x7FFFFFFFFFFE9E31LL, // 178
    0x7FFFFFFFFFFF0530LL, // 179
    0x7FFFFFFFFFFF4E88LL, // 180
    0x7FFFFFFFFFFF82AALL, // 181
    0x7FFFFFFFFFFFA7A6LL, // 182
    0x7FFFFFFFFFFFC1D6LL, // 183
    0x7FFFFFFFFFFFD458LL, // 184
    0x7FFFFFFFFFFFE166LL, // 185
    0x7FFFFFFFFFFFEA97LL, // 186
    0x7FFFFFFFFFFFF10CLL, // 187
    0x7FFFFFFFFFFFF594LL, // 188
    0x7FFFFFFFFFFFF8C0LL, // 189
    0x7FFFFFFFFFFFFAF7LL, // 190
    0x7FFFFFFFFFFFFC83LL, // 191
    0x7FFFFFFFFFFFFD96LL, // 192
    0x7FFFFFFFFFFFFE56LL, // 193
    0x7FFFFFFFFFFFFEDALL, // 194
    0x7FFFFFFFFFFFFF36LL, // 195
    0x7FFFFFFFFFFFFF75LL, // 196
    0x7FFFFFFFFFFFFFA1LL, // 197
    0x7FFFFFFFFFFFFFBFLL, // 198
    0x7FFFFFFFFFFFFFD4LL, // 199
    0x7FFFFFFFFFFFFFE2LL, // 200
    0x7FFFFFFFFFFFFFECLL, // 201
    0x7FFFFFFFFFFFFFF2LL, // 202
    0x7FFFFFFFFFFFFFF7LL, // 203
    0x7FFFFFFFFFFFFFFALL, // 204
    0x7FFFFFFFFFFFFFFCLL, // 205
    0x7FFFFFFFFFFFFFFDLL, // 206
    0x7FFFFFFFFFFFFFFELL, // 207
    0x7FFFFFFFFFFFFFFFLL, // 208
}; // cdt_v

// memory requirements:
//      512 samples:  8652 bytes
//      256 samples:  5580 bytes
//      128 samples:  4044 bytes
//       64 samples:  3276 bytes
//       32 samples:  2892 bytes
// table alone: 1672 bytes

#endif 