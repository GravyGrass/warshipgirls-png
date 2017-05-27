#pragma once

#include <array>
#include <istream>
#include <ostream>
#include <vector>
#include <cassert>
#include "AES.h"
#include "Struct.h"

/**
 * 从流中读取一些数据
 */
template <int _Value>
static std::array<char, _Value> ReadSome(std::istream &stream)
{
	std::array<char, _Value> buffer;
	stream.read(buffer.data(), _Value);
	return buffer;
}

/**
 * 从流中读取一个 POD 对象
 */
template <typename T>
inline T ReadObject(std::istream &stream)
{
	T obj;
	stream.read(reinterpret_cast<char*>(&obj), sizeof(obj));
	return obj;
}

/**
 * 从流中读取大量数据
 */
static std::vector<char> ReadLarge(std::istream &stream, const int readsize)
{
	std::vector<char> buffer(readsize);
	stream.read(buffer.data(), readsize);
	return buffer;
}

/**
 * 拷贝数据到流
 */
static void SteamCopy(std::ostream &stream, const void *data, uint32_t size)
{
	assert(data && size > 0);
	const char *p = static_cast<const char *>(data);
	stream.write(p, size);
}

/**
 * 移动流中数据到另一个流
 */
static void StreamMove(std::ostream &target, std::istream &source, const uint32_t size)
{
	std::vector<char> buffer = ReadLarge(source, size);
	SteamCopy(target, buffer.data(), size);
}

/**
 * 数据块加密
 */
static void EncryptBlock(std::vector<char> &ss, const aes_key &key)
{
	const uint32_t contents_size = uint32_t(ss.size());
	assert(contents_size);

	uint32_t real_size = contents_size;
	if (real_size % AES_BLOCK_SIZE) real_size += AES_BLOCK_SIZE - contents_size % AES_BLOCK_SIZE;

	std::vector<uint8_t> buffer(ss.cbegin(), ss.cend());
	buffer.resize(real_size);
	AES::EncryptData(&buffer[0], real_size, key);
	ss.assign(buffer.cbegin(), buffer.cbegin() + ss.size());
}

/*
 * 数据块解密
 */
static void DecryptBlock(std::vector<char> &ss, const aes_key &key)
{
	const uint32_t contents_size = uint32_t(ss.size());
	assert(contents_size);

	uint32_t real_size = contents_size;
	if (real_size % AES_BLOCK_SIZE) real_size += AES_BLOCK_SIZE - contents_size % AES_BLOCK_SIZE;

	std::vector<uint8_t> buffer(ss.cbegin(), ss.cend());
	buffer.resize(real_size);
	AES::DecryptData(&buffer[0], real_size, key);
	ss.assign(buffer.cbegin(), buffer.cbegin() + ss.size());
}
