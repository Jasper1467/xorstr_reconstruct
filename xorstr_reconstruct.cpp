#include <cstdint>
#include <cstdio>
#include <cstring>
#include <iostream>

#ifdef __TIME__
#undef __TIME__
#define __TIME__ "12:34:56"
#endif

#include "external/xorstr.hpp"

// FNV-1a hash constants
constexpr uint32_t FNV_prime = 16777619u;
constexpr uint32_t offset_basis = 2166136261u;

// Generate key from __TIME__
constexpr uint32_t generate_key(const char* time_str)
{
    uint32_t hash = offset_basis;
    while (*time_str)
    {
        hash ^= static_cast<uint32_t>(*time_str++);
        hash *= FNV_prime;
    }
    return hash;
}

// Generate a 64-bit key using the library's key generation method
uint64_t generate_key64(const char* time_str, size_t offset)
{
    uint32_t part1 = generate_key(time_str) + offset;
    uint32_t part2 = generate_key(reinterpret_cast<const char*>(&part1));
    return (static_cast<uint64_t>(part1) << 32) | part2;
}

// Decrypt the string using the key
const char* decrypt_string(const char* str, size_t size, uint64_t key)
{
    char* decrypted;
    for (size_t i = 0; i < size; ++i)
    {
        decrypted = (char*)((int)str[i] ^ reinterpret_cast<char*>(&key)[i % sizeof(key)]);
    }

    return decrypted;
}

int main()
{
    // Encrypted string (example, replace with the actual encrypted string)
    const char* encrypted_str = xorstr_("test");
    size_t size = sizeof(encrypted_str) - 1; // Excluding null terminator

    // Generate the key (replace "__TIME__" with the actual time string used
    // during encryption)
    uint64_t key = generate_key64("12:34:56", 0);

    // Decrypt the string
    decrypt_string(encrypted_str, size, key);

    // Print the decrypted string
    std::cout << "Decrypted string: " << encrypted_str << std::endl;

    return 0;
}
