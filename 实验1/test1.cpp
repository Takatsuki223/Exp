#include <iostream>
#include <iomanip>
#include <vector>
#include <string>

using namespace std;

// AES S盒（加密时使用，字节代换步骤用）
const unsigned char sbox[256] = {
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
};

// AES 逆S盒（解密时使用）
const unsigned char inv_sbox[256] = {
    0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
    0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
    0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
    0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
    0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
    0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
    0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
    0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
    0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
    0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
    0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
    0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
    0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
    0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
    0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D
};

// 轮常数（密钥扩展过程中使用，确保每一轮的轮密钥都有足够差异）
const unsigned char Rcon[11] = {
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36
};

// 打印状态矩阵
void printState(const vector<vector<unsigned char>>& state, const string& step, int round) {
    cout << step << " Round " << round << ":" << endl;
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            cout << hex << setw(2) << setfill('0') << (int)state[j][i] << " ";
        }
        cout << endl;
    }
    cout << endl;
}

// 密钥扩展
vector<vector<vector<unsigned char>>> keyExpansion(const vector<unsigned char>& key) {
    vector<vector<vector<unsigned char>>> roundKeys(11, vector<vector<unsigned char>>(4, vector<unsigned char>(4)));

    // 初始密钥：直接作为第0轮密钥
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            roundKeys[0][i][j] = key[i + j * 4];
        }
    }

    // 后续轮密钥处理：
    for (int round = 1; round < 11; round++) {
        vector<vector<unsigned char>> prevKey = roundKeys[round - 1];
        vector<vector<unsigned char>> newKey(4, vector<unsigned char>(4));

        // 1.对前一轮密钥的第一列特殊处理
        vector<unsigned char> temp(4);
        for (int i = 0; i < 4; i++) {
            temp[i] = prevKey[i][3];  // 取上一轮密钥的最后一列
        }

        // 2.循环左移：4个数据循环左移
        unsigned char temp_byte = temp[0];
        temp[0] = temp[1];
        temp[1] = temp[2];
        temp[2] = temp[3];
        temp[3] = temp_byte;

        // 3.S盒替换：字节映射到S盒中进行值的替换
        for (int i = 0; i < 4; i++) {
            temp[i] = sbox[temp[i]];
        }

        // 4.与轮常数异或：初始变换
        temp[0] ^= Rcon[round];

        // 5.生成新密钥的第一列
        for (int i = 0; i < 4; i++) {
            newKey[i][0] = prevKey[i][0] ^ temp[i];
        }

        // 6.生成其余列：简单异或生成
        for (int j = 1; j < 4; j++) {
            for (int i = 0; i < 4; i++) {
                newKey[i][j] = newKey[i][j - 1] ^ prevKey[i][j];
            }
        }

        roundKeys[round] = newKey;
    }

    return roundKeys;
}

// 1.字节替换（加密）
void subBytes(vector<vector<unsigned char>>& state) {
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            state[i][j] = sbox[state[i][j]];
        }
    }
}

// 1.逆字节替换（解密）
void invSubBytes(vector<vector<unsigned char>>& state) {
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            state[i][j] = inv_sbox[state[i][j]];
        }
    }
}

// 2.行移位（加密）
void shiftRows(vector<vector<unsigned char>>& state) {
    // 第一行不移位

    // 第二行左移1位
    unsigned char temp = state[1][0];
    state[1][0] = state[1][1];
    state[1][1] = state[1][2];
    state[1][2] = state[1][3];
    state[1][3] = temp;

    // 第三行左移2位（交换两次）
    temp = state[2][0];
    state[2][0] = state[2][2];
    state[2][2] = temp;
    temp = state[2][1];
    state[2][1] = state[2][3];
    state[2][3] = temp;

    // 第四行左移3位（相当于右移1位）
    temp = state[3][3];
    state[3][3] = state[3][2];
    state[3][2] = state[3][1];
    state[3][1] = state[3][0];
    state[3][0] = temp;
}

// 2.逆行移位（解密）
void invShiftRows(vector<vector<unsigned char>>& state) {
    // 第一行不移位

    // 第二行右移1位
    unsigned char temp = state[1][3];
    state[1][3] = state[1][2];
    state[1][2] = state[1][1];
    state[1][1] = state[1][0];
    state[1][0] = temp;

    // 第三行右移2位（与左移2位操作相同）
    temp = state[2][0];
    state[2][0] = state[2][2];
    state[2][2] = temp;
    temp = state[2][1];
    state[2][1] = state[2][3];
    state[2][3] = temp;

    // 第四行右移3位（相当于左移1位）
    temp = state[3][0];
    state[3][0] = state[3][1];
    state[3][1] = state[3][2];
    state[3][2] = state[3][3];
    state[3][3] = temp;
}

// 修正的有限域乘法函数
unsigned char gmul(unsigned char a, unsigned char b) {
    unsigned char p = 0;
    unsigned char hi_bit_set;

    for (int i = 0; i < 8; i++) {
        if (b & 1) {
            p ^= a;
        }

        hi_bit_set = (a & 0x80);
        a <<= 1;

        if (hi_bit_set) {
            a ^= 0x1b; // AES的不可约多项式: x^8 + x^4 + x^3 + x + 1
        }

        b >>= 1;
    }

    return p;
}

// 3.列混合（加密）
void mixColumns(vector<vector<unsigned char>>& state) {
    unsigned char a[4], b[4];

    for (int c = 0; c < 4; c++) {
        for (int i = 0; i < 4; i++) {
            a[i] = state[i][c];
        }

        b[0] = gmul(0x02, a[0]) ^ gmul(0x03, a[1]) ^ a[2] ^ a[3];
        b[1] = a[0] ^ gmul(0x02, a[1]) ^ gmul(0x03, a[2]) ^ a[3];
        b[2] = a[0] ^ a[1] ^ gmul(0x02, a[2]) ^ gmul(0x03, a[3]);
        b[3] = gmul(0x03, a[0]) ^ a[1] ^ a[2] ^ gmul(0x02, a[3]);

        for (int i = 0; i < 4; i++) {
            state[i][c] = b[i];
        }
    }
}

// 3.逆列混合（解密）
void invMixColumns(vector<vector<unsigned char>>& state) {
    unsigned char a[4], b[4];

    for (int c = 0; c < 4; c++) {
        // 获取当前列
        for (int i = 0; i < 4; i++) {
            a[i] = state[i][c];
        }
        // 矩阵：[0x0E, 0x0B, 0x0D, 0x09]
        //      [0x09, 0x0E, 0x0B, 0x0D]
        //      [0x0D, 0x09, 0x0E, 0x0B]
        //      [0x0B, 0x0D, 0x09, 0x0E]
        b[0] = gmul(0x0E, a[0]) ^ gmul(0x0B, a[1]) ^ gmul(0x0D, a[2]) ^ gmul(0x09, a[3]);
        b[1] = gmul(0x09, a[0]) ^ gmul(0x0E, a[1]) ^ gmul(0x0B, a[2]) ^ gmul(0x0D, a[3]);
        b[2] = gmul(0x0D, a[0]) ^ gmul(0x09, a[1]) ^ gmul(0x0E, a[2]) ^ gmul(0x0B, a[3]);
        b[3] = gmul(0x0B, a[0]) ^ gmul(0x0D, a[1]) ^ gmul(0x09, a[2]) ^ gmul(0x0E, a[3]);

        // 存回状态矩阵
        for (int i = 0; i < 4; i++) {
            state[i][c] = b[i];
        }
    }
}

// 4.轮密钥加
void addRoundKey(vector<vector<unsigned char>>& state, const vector<vector<unsigned char>>& roundKey) {
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            state[i][j] ^= roundKey[i][j];
        }
    }
}

// AES加密
vector<unsigned char> aesEncrypt(const vector<unsigned char>& plaintext, const vector<unsigned char>& key) {
    // 初始化状态矩阵 
    vector<vector<unsigned char>> state(4, vector<unsigned char>(4));
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            state[i][j] = plaintext[i + j * 4];
        }
    }

    // 密钥扩展
    auto roundKeys = keyExpansion(key);

    cout << "=== AES加密过程 ===" << endl;

    // 初始轮密钥加
    addRoundKey(state, roundKeys[0]);
    printState(state, "初始轮密钥加后", 0);

    // 9轮主循环
    for (int round = 1; round < 10; round++) {
        subBytes(state);
        printState(state, "字节代换", round);

        shiftRows(state);
        printState(state, "行移位", round);

        mixColumns(state);
        printState(state, "列混合", round);

        addRoundKey(state, roundKeys[round]);
        printState(state, "轮密钥加", round);
    }

    // 最后一轮
    subBytes(state);
    printState(state, "字节代换", 10);

    shiftRows(state);
    printState(state, "行移位", 10);

    addRoundKey(state, roundKeys[10]);
    printState(state, "最后的轮密钥加", 10);

    // 转换为输出 
    vector<unsigned char> ciphertext(16);
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            ciphertext[i + j * 4] = state[i][j];
        }
    }

    return ciphertext;
}

// AES解密
vector<unsigned char> aesDecrypt(const vector<unsigned char>& ciphertext, const vector<unsigned char>& key) {
    // 1. 正确初始化状态矩阵 (4x4)
    vector<vector<unsigned char>> state(4, vector<unsigned char>(4));
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            state[i][j] = ciphertext[i + j * 4];
        }
    }

    auto roundKeys = keyExpansion(key);

    // --- 第一步：逆初始轮 (对应加密的最后一轮，没有列混合) ---
    addRoundKey(state, roundKeys[10]);
    printState(state, "逆初始轮密钥加", 10);

    invShiftRows(state);
    printState(state, "逆行移位", 10);

    invSubBytes(state);
    printState(state, "逆字节代换", 10);

    // --- 第二步：逆中间 9 轮 (Round 9 倒数到 Round 1) ---
    for (int round = 9; round >= 1; round--) {
        // 顺序必须是：AddRoundKey -> InvMixColumns -> InvShiftRows -> InvSubBytes
        addRoundKey(state, roundKeys[round]);
        printState(state, "轮密钥加", round);

        invMixColumns(state);
        printState(state, "逆列混合", round);

        invShiftRows(state);
        printState(state, "逆行移位", round);

        invSubBytes(state);
        printState(state, "逆字节代换", round);
    }

    // --- 第三步：逆最终轮 (对应加密前的初始 AddRoundKey) ---
    addRoundKey(state, roundKeys[0]);
    printState(state, "最后的轮密钥加 (初始密钥)", 0);

    // 转换为输出向量
    vector<unsigned char> plaintext(16);
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            plaintext[i + j * 4] = state[i][j];
        }
    }
    return plaintext;
}
int main() {
    // 测试向量：NIST FIPS 197 Appendix B示例
    vector<unsigned char> plaintext = {
        0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d,
        0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34
    };

    vector<unsigned char> key = {
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
    };

    cout << "128位明文:  ";
    for (auto byte : plaintext) {
        cout << hex << setw(2) << setfill('0') << (int)byte << " ";
    }
    cout << endl;

    cout << "128位密钥:  ";
    for (auto byte : key) {
        cout << hex << setw(2) << setfill('0') << (int)byte << " ";
    }
    cout << endl << endl;

    // 加密
    vector<unsigned char> ciphertext = aesEncrypt(plaintext, key);

    cout << "128位密文:  ";
    for (auto byte : ciphertext) {
        cout << hex << setw(2) << setfill('0') << (int)byte << " ";
    }
    cout << endl;

    // 验证加密结果（与标准结果对比）
    vector<unsigned char> expected = {
        0x39, 0x25, 0x84, 0x1d, 0x02, 0xdc, 0x09, 0xfb,
        0xdc, 0x11, 0x85, 0x97, 0x19, 0x6a, 0x0b, 0x32
    };

    cout << "期望密文:   ";
    for (auto byte : expected) {
        cout << hex << setw(2) << setfill('0') << (int)byte << " ";
    }
    cout << endl;

    bool correct = true;
    for (int i = 0; i < 16; i++) {
        if (ciphertext[i] != expected[i]) {
            correct = false;
            cout << "Mismatch at position " << i << ": got " << hex << (int)ciphertext[i]
                << ", expected " << hex << (int)expected[i] << endl;
            break;
        }
    }

    if (correct) {
        cout << "加密结果与预期值匹配！" << endl;
    }
    else {
        cout << "加密结果与预期值不匹配！" << endl;
    }

    // 使用期望的密文进行解密
    cout << "\n=== 使用期望密文进行解密 ===" << endl;
    vector<unsigned char> decrypted = aesDecrypt(expected, key);

    cout << "\n解密得到的明文: ";
    for (auto byte : decrypted) {
        cout << hex << setw(2) << setfill('0') << (int)byte << " ";
    }
    cout << endl;

    cout << "原始明文:       ";
    for (auto byte : plaintext) {
        cout << hex << setw(2) << setfill('0') << (int)byte << " ";
    }
    cout << endl;

    // 验证解密结果
    bool decrypt_correct = true;
    for (int i = 0; i < 16; i++) {
        if (decrypted[i] != plaintext[i]) {
            decrypt_correct = false;
            cout << "解密不匹配 at position " << i << ": got " << hex << (int)decrypted[i]
                << ", expected " << hex << (int)plaintext[i] << endl;
            break;
        }
    }

    if (decrypt_correct) {
        cout << "解密结果与原始明文匹配！" << endl;
    }
    else {
        cout << "解密结果与原始明文不匹配！" << endl;
    }

    return 0;
}