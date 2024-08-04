
mod auth;

use sqlite::{self, State, Value};
use std::path::Path;
use std::fs::File;
use auth::{decrypt, derive_pw, encrypt_secret};
pub struct Service {
  db: sqlite::Connection
}

pub struct User {
  pub username: String,
  secret: Vec<u8>,
}

pub struct Password {
  pub username: String,
  pub destination: String,
  pub password: String
}

impl Password {
  fn new(username: String, destination: String, password: String) -> Self {
    Self {
      username,
      destination,
      password
    }
  }

  pub fn print(&self) {
    println!("Username:       {}", self.username);
    println!("Destination:    {}", self.destination);
    println!("Password:       {}", self.password);
  }
}


impl User {
  fn new(username: String, secret: Vec<u8>) -> Self {
    Self {
      username,
      secret,
    }
  }

  pub fn save_password(&self, s: &Service, password: String, destination: String) -> Result<&str, &str> {
    let encrypted_password = auth::encrypt(self.secret.clone(), password);

    let save_pw_query = "
      INSERT INTO passwords (username, destination, encrypted_password) VALUES (
        :username,
        :destination,
        :encrypted_password
      )
    ";

    let mut statement = s.db.prepare(save_pw_query).unwrap();
    statement.bind::<&[(_, Value)]>(&[
      (":username", self.username.clone().into()),
      (":destination", destination.clone().into()),
      (":encrypted_password", encrypted_password.clone().into())
    ]).unwrap();

    let ok = statement.next().is_ok();
    if !ok {
      return Err("error inserting password");
    } else {
      return Ok("password inserted");
    }
  }

  pub fn get_passwords(&self, s: &Service) -> Vec<Password>{

    let get_passwords_query = "
      SELECT * FROM passwords WHERE username = :username;
    ";

    let mut statement = s.db.prepare(get_passwords_query).unwrap();
    statement.bind::<&[(_, Value)]>(&[
      (":username", self.username.clone().into())
    ]).unwrap();

    let mut pws:Vec<Password> = Vec::new();

    while let Ok(State::Row) = statement.next() {
      let u = statement.read::<String, _>("username").unwrap();
      let d = statement.read::<String, _>("destination").unwrap();
      let p = statement.read::<Vec<u8>, _>("encrypted_password").unwrap();

      let decrypted_password = auth::decrypt_password(&self.secret, &p);

      if decrypted_password.is_ok() {
        pws.push(Password::new(u, d, decrypted_password.unwrap()))
      }
    }

    pws
  }
}


impl Service {
  pub fn new(db: sqlite::Connection) -> Self {
    Self {
      db
    }
  }




  pub fn login(&self, username: String, password: String) -> Result<User, &str> {
    println!("logging in");
    let pw_hash = derive_pw(password.clone());

    let get_user = "
      SELECT * FROM auth WHERE username = :username;
    ";

    let mut statement = self.db.prepare(get_user).unwrap();
    statement.bind((":username", username.as_str())).unwrap();

    let mut u: String = String::new();
    let mut p: Vec<u8> = Vec::new();
    let mut s: Vec<u8> = Vec::new();

    while let Ok(State::Row) = statement.next() {
      u = statement.read::<String, _>("username").unwrap();
      p = statement.read::<Vec<u8>, _>("password_hash").unwrap();
      s = statement.read::<Vec<u8>, _>("encrypted_secret").unwrap();
    }

    let mut ok = false;
    if u == username && p == pw_hash {
      ok = decrypt(password.clone(), &s).is_ok();
    }

    if ok {
      let decrypted_secret = decrypt(password, &s).unwrap();
      let acc = User::new(u, decrypted_secret);
      return Ok(acc);
    } else {
      return Err("incorrect password");
    }

  }



  // TODO: implement public key from secret for route authentication
  pub fn create_account(&self, username: String, password: String) -> Result<User, &str> {
    let pw_bytes = &derive_pw(password.clone());
    let encrypted_secret = encrypt_secret(password.clone());
    let decrypted_secret = decrypt(password, &encrypted_secret).unwrap();

    println!("creating account");

    let save_account = "
      INSERT INTO auth (username, password_hash, encrypted_secret) VALUES (
        :username,
        :password_hash,
        :encrypted_secret
      );
    ";

    let mut statement = self.db.prepare(save_account).unwrap();
    statement.bind::<&[(_, Value)]>(&[
      (":username", username.clone().into()),
      (":password_hash", pw_bytes.to_vec().into()),
      (":encrypted_secret", encrypted_secret.clone().into())
    ]).unwrap();

    let ok = statement.next().is_ok();
    if !ok {
      return Err("account already exists")
    }

    let acc = User::new(username, decrypted_secret);
    return Ok(acc)
  }

  fn init_tables(&self) {
    let create_auth_table = "
      CREATE TABLE IF NOT EXISTS auth (
        username TEXT,
        password_hash BLOB,
        encrypted_secret BLOB,
        UNIQUE(username)
      );
    ";

    self.db.execute(create_auth_table).unwrap();

    let create_pw_table = "
      CREATE TABLE IF NOT EXISTS passwords (
        username TEXT,
        destination TEXT,
        encrypted_password BLOB,
        FOREIGN KEY(username)
        REFERENCES auth(username)
      );
    ";

    self.db.execute(create_pw_table).unwrap();
  }
}




pub fn connect(path: String) -> Service {
  let exists = Path::new(&path).exists();
  println!("exists: {}", exists);
  if !exists {
    let _ = File::create_new(&path);
    println!("made file at {}", &path)
  }
  let connection = sqlite::open(path.clone()).unwrap();
  let s = Service::new(connection);
  s.init_tables();
  s
}

