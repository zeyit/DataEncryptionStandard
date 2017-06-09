package main

import (
	"encoding/binary"
)

type Des struct {
	subkeys [16]uint64
	//aa uint64
}

func (this *Des) init(key []byte) {
	keyBlock := binary.BigEndian.Uint64(key)
	keyLeft, keyRight := ((uint32(keyBlock>>28)<<4)>>4), ((uint32(keyBlock)<<4)>>4)

	for i := 0; i < 16; i++ {
		if i !=0 {
			bitCycle(&keyLeft)
			bitCycle(&keyRight)
		}
		//soldan 4 bit atma
		left64 := uint64((keyLeft<<8)>>8)<<24
		//sagdan 4 bit atma
		right64 := uint64(keyRight>>4)
		this.subkeys[i] = (left64 | right64)
	}
}


func  bitCycle(key *uint32)  {
	//28 bit in solundan  1 bit alma
	bit := *key>>27
	//1 bit i key in başına koyma
	*key<<=1
	*key |=bit
}

func (this *Des) Encryption(text []byte) []byte {
	//b := make([]byte, 8)
	//binary.LittleEndian.PutUint64(b, this.cryptBlock(text, false))
	return uInt64ToByte(this.cryptBlock(text, false))
}

func (this *Des) Decryption(text []byte) []byte {
	//b := make([]byte, 8)
	//binary.LittleEndian.PutUint64(b, this.cryptBlock(text, true))
	return uInt64ToByte(this.cryptBlock(text, true))
}

func (this *Des) cryptBlock(text []byte, isDecrypt bool) uint64 {
	block :=binary.BigEndian.Uint64(text)
	left, right := uint32(block>>32), uint32(block)

	var subkey uint64
	for i := 0; i < 16; i++ {
		if isDecrypt {
			subkey = this.subkeys[15-i]
		} else {
			subkey = this.subkeys[i]
		}

		left, right = right, left^Ffunc(right, subkey)
	}

	result := (uint64(right) << 32) | uint64(left)
	return result
}

func  byteToUint64(b []byte) uint64 {
	var result uint64
	for i:=7;i>=0 ;i--  {
		result <<=8
		result |=uint64(b[i])
	}
	return result
}

func uInt64ToByte(result uint64 ) []byte {
	b :=make([]byte,8)
	for i:=7;i>=0 ; i-- {
		tmp :=uint8(result>>(uint8(i*8)))
		b[7-i]=byte(tmp)
	}
	return b
}

func Ffunc(right uint32, key uint64) uint32 {
	sBoxLocations := key ^ expandFunc(right)
	sBoxLocations <<=16
	sBoxLocations >>=16
	var sBoxResult uint32

	for i := 0; i < 8; i++ {

		shift :=uint(6*(7-i))
		sBoxLoc := uint8(sBoxLocations>>shift)
		shift =uint(6*(1+i)+16)
		sBoxLocations <<=shift

		sBoxLoc <<=2
		sBoxLoc >>=2

		row := sBoxLoc & 0x03 // 0000 0011    1(0) 1(1) 1(2) 1(3)
		col := sBoxLoc & 0x0f // 0000 1111

		sBoxResult ^= uint32(sBoxes[i][row][col])
	}
	return sBoxResult
}

func expandFunc(right uint32) uint64 {
	var result uint64
	for i := 0; i < 8; i++ {
		shift :=uint(4*(7-i))
		blog4 := int8(right>>shift)

		shift =uint(4*(1+i))
		right <<=shift

		right <<=4
		row := blog4 & 0x05 // 0110    1(0) 1(1) 1(2) 1(3)
		col := blog4 & 0x07 // 0111
		val := uint64(expansion[row*8+col])
		result =result << 6
		result |= val
	}
	//fmt.Println(result)
	return result
}

var expansion = [48]uint8{
	32, 1, 3, 1, 2, 4, 3, 6,
	4, 5, 5, 7, 28, 30, 7, 9,
	9, 7, 10, 8, 22, 11, 11, 15,
	29, 12, 14, 17, 15, 16, 12, 18,
	13, 23, 19, 21, 15, 17, 14, 18,
	31, 20, 21, 20, 24, 25, 26, 27,
}

var sBoxes = [8][4][16]uint8{
	// S-box 1
	{
		{14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7},
		{0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8},
		{4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0},
		{15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13},
	},
	// S-box 2
	{
		{15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10},
		{3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5},
		{0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15},
		{13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9},
	},
	// S-box 3
	{
		{10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8},
		{13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1},
		{13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7},
		{1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12},
	},
	// S-box 4
	{
		{7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15},
		{13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9},
		{10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4},
		{3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14},
	},
	// S-box 5
	{
		{2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9},
		{14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6},
		{4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14},
		{11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3},
	},
	// S-box 6
	{
		{12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11},
		{10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8},
		{9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6},
		{4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13},
	},
	// S-box 7
	{
		{4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1},
		{13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6},
		{1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2},
		{6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12},
	},
	// S-box 8
	{
		{13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7},
		{1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2},
		{7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8},
		{2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11},
	},
}
