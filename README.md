# PVOABE
This repository implements all algorithms of PVOABE, you need to install  `go` to run it

This repo utilizes the Gofe repository:https://github.com/fentec-project/gofe

## PVGSS
PVGSS implements all the algorithms of Publicly Verified Generalized Secret Sharing (PVGSS),you can run
```bash
go test -v ./PVGSS
```
to test all the functions of PVGSS.

## PVOABE
The main.go file implements all the functions of PVOABE. You can run main_test.go to test all the functions.
```bash
go test -v 
```
## TEST
We also tested several schemes proposed in similar papers for comparison
 * Verifiable Outsourced Attribute-Based Encryption Scheme for Cloud-Assisted Mobile E-health System
 * Efficient Ciphertext-Policy Attribute-Based Encryption Constructions with Outsourced Encryption and Decryption
You can test them by run
```bash
go test -v ./VOABE
```
```bash
go test -v ./ECPABE
```