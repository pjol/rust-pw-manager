
use aes_gcm::{aead::Aead, KeyInit};
use pbkdf2;
use sha2::{digest::generic_array::GenericArray, Sha256};
use std::fmt::Write;

pub fn derive_pw(password: String) -> [u8; 20] {
  let mut res = [0u8; 20];
  let salt = b"epsom";
  let password = password.as_bytes();
  let rounds = 150_000;
  pbkdf2::pbkdf2_hmac::<Sha256>(password, salt, rounds, &mut res);
  res
}




pub fn u8_to_string(bytes: &[u8]) -> String {
  let mut s = String::new();
  for &byte in bytes {
    write!(&mut s, "{:X}", byte).expect("Unable to write bytes to string")
  }
  s
}




pub fn generate_key_from_string(string: String) -> [u8; 32] {
  let bytes = string.as_bytes();
  let mut result: [u8; 32] = [0; 32];
  for (i, byte) in bytes.iter().enumerate() {
    result[i] = *byte
  }
  result
}




pub fn encrypt_secret(password: String) -> Vec<u8> {
  let key = aes_gcm::Aes256Gcm::generate_key(aes_gcm::aead::OsRng);
  let key_bytes: &[u8] = key.as_slice().try_into().unwrap();

  let password_bytes: &[u8; 32] = &generate_key_from_string(password);
  let cipher = aes_gcm::Aes256Gcm::new(password_bytes.into());

  let nonce: sha2::digest::generic_array::GenericArray<u8, _> = aes_gcm::Nonce::from_iter(*password_bytes);

  let encrypted_secret = cipher.encrypt(&nonce, key_bytes).unwrap();

  encrypted_secret
}



pub fn encrypt(key: Vec<u8>, message: String) -> Vec<u8> {
  let k = sha2::digest::generic_array::GenericArray::clone_from_slice(&key);
  let cipher = aes_gcm::Aes256Gcm::new(&k);

  let nonce: sha2::digest::generic_array::GenericArray<u8, _> = aes_gcm::Nonce::from_iter(key.clone());

  let encrypted_secret = cipher.encrypt(&nonce, message.as_bytes()).unwrap();

  encrypted_secret
}

pub fn decrypt_password(key: &[u8], encrypted: &[u8]) -> Result<String, String> {
  let cipher: aes_gcm::AesGcm<aes_gcm::aes::Aes256, _, _> = aes_gcm::Aes256Gcm::new(key.into());

  let nonce: sha2::digest::generic_array::GenericArray<u8, _> = aes_gcm::Nonce::from_iter(key.to_vec());

  let decrypted_secret: Result<Vec<u8>, aes_gcm::Error> = cipher.decrypt(&nonce, encrypted.clone());

  if decrypted_secret.is_ok() {
    return Ok(String::from_utf8(decrypted_secret.unwrap()).unwrap())
  } else {
    return Err(String::from("error decrypting secret"))
  }
}




pub fn decrypt(password: String, encrypted: &[u8]) -> Result<Vec<u8>, aes_gcm::Error> {
  let password_bytes: &[u8; 32] = &generate_key_from_string(password);
  let cipher = aes_gcm::Aes256Gcm::new(password_bytes.into());

  let nonce: sha2::digest::generic_array::GenericArray<u8, _> = aes_gcm::Nonce::from_iter(*password_bytes);

  let decrypted_secret: Result<Vec<u8>, aes_gcm::Error> = cipher.decrypt(&nonce, encrypted);

  decrypted_secret
}