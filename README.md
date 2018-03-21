# Mask - A platform independent reverse shell over TCP using TLS.

#####  Mask is a reverse shell over TCP using TLS and MaskManager is a manager for Mask .
#####  Certificate pinning is implemented to escape from MITM

## Getting Started

##### git clone https://github.com/diljithishere/mask.git
##### cd mask/src
#### Create certs and Finger Print
#### openssl genrsa -out server.key 2048
#### openssl req -new -x509 -days 1826 -key server.key -out server.crt
#### openssl x509 -fingerprint -sha256 -noout -in server.crt (Keep the output to update the mask.go source file)
#### go get github.com/fatih/color
#### Build Mask 
#### Update your Maskmanager ip  { MASKMANAGERIP := "ip:port" }
#### Update your fingerprint . { PINNEDFPRINT="YOUR:FINGER:PRINT" }
##### GOOS=windows GOARCH=386 go build -o mask.exe mask.go (For windows executable)
##### go build mask.go (Linux)

#### Build MaskManager 
##### go build -o maskmanager.exe maskmanager.go (Windows)
##### go build maskmanager (Linux)
#### Run Maskmanager 
##### ./maskmanager

#### Once if the mask runs Maskmanager's prompt will change to MaskTunnel
#### Run Normal shell commands based on OS plus you can download files usng get command . {get filename} {bye command will stop communication}


### Prerequisites

#### Go 1.9

## Built With
#### Go Lang

## Author

* **Diljith S** - *Initial work* - (https://github.com/diljithishere)
