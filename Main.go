package main

import (
	"fmt"
	"bufio"
	"os"
	"io"
	"math/rand"
	"strconv"
	"time"
)

func main() {

	var filepath,key,operation string
	reader := bufio.NewReader(os.Stdin)

	fmt.Println("----------Dosya ile şifreleme -------------")
	fmt.Print("Dosya adı:")
	fmt.Scanln(&filepath)

	fmt.Print("Key girin:")
	fmt.Scanln(&key)

	fmt.Println("1) Şifreleme 2) Şifre Çözme")
	fmt.Scanln(&operation)
	des := new(Des)
	des.init([]byte(key))

	file ,err :=os.Open(filepath);
	if  err !=nil {
		panic(err)
	}
	defer  file.Close()

	rand.Seed(time.Now().Unix())
	number :=strconv.Itoa(rand.Intn(100))
	outputFile, err := os.Create("Output"+number+".txt")

	if err != nil {
		panic(err)
	}
	defer outputFile.Close()

	buf := make([]byte, 8)
	for{
		n, err := file.Read(buf)
		if err != nil && err != io.EOF {
			panic(err)
		}
		if n == 0 {
			break
		}
		if n !=8{
			for ; n<8;n++{
				buf[n]=' '
			}
		}
		var txt []byte
		if operation =="1"{
			txt = des.Encryption(buf)
		}else{
			txt = des.Decryption(buf)
		}
		outputFile.Write(txt)
	}
	fmt.Printf("İşlem Tamamlandı")
	filepath ,_= reader.ReadString('\n')
}
