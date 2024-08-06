
mod auth;

use aes_gcm::aead::OsRng;
use sqlite::{self, State, Value};
use uuid::Uuid;
use core::panic;
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

// TODO: add owner_username and login_username to Password
pub struct Password {
  pub id: String,
  pub owner_username: String,
  pub login_username: String,
  pub destination: String,
  password: String
}

impl Password {
  fn new(id: String, owner_username: String, login_username: String, destination: String, password: String) -> Self {

    Self {
      id,
      owner_username,
      login_username,
      destination,
      password
    }
  }

  pub fn print(&self) {
    println!("Id:             {}", self.id);
    println!("Owner:          {}", self.owner_username);
    println!("Destination:    {}", self.destination);
    println!("Username:       {}", self.login_username);
  }

  pub fn copy(&self) {
    let pw = &self.password;
    cli_clipboard::set_contents(pw.clone()).unwrap();
  }
}


impl User {
  fn new(username: String, secret: Vec<u8>) -> Self {
    Self {
      username,
      secret,
    }
  }

  pub fn save_password(&self, s: &Service, login_username: String, password: String, destination: String) -> Result<&str, &str> {
    let encrypted_password = auth::encrypt(self.secret.clone(), password);

    let id = Uuid::new_v4().to_string();

    let save_pw_query = "
      INSERT INTO passwords (id, owner_username, login_username, destination, encrypted_password) VALUES (
        :id,
        :owner_username,
        :login_username,
        :destination,
        :encrypted_password
      )
    ";

    let mut statement = s.db.prepare(save_pw_query).unwrap();
    statement.bind::<&[(_, Value)]>(&[
      (":id", id.clone().into()),
      (":owner_username", self.username.clone().into()),
      (":login_username", login_username.clone().into()),
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

  pub fn remove_password(&self, s: &Service, id: String, password: String) -> Result<&str, &str> {

    let username = self.username.clone();

    let u = s.login(username, password);

    if !u.is_ok() {
      return Err("unauthorized");
    }

    if u.unwrap().secret != self.secret {
      return Err("unauthorized");
    }

    let delete_password_query = "
      DELETE FROM passwords WHERE id = :id;
    ";

    let mut statement = s.db.prepare(delete_password_query).unwrap();
    statement.bind::<&[(_, Value)]>(&[
      (":id", id.clone().into()),
    ]).unwrap();

    let ok = statement.next().is_ok();

    if !ok {
      return Err("error deleting password")
    } else {
      return Ok("deleted")
    }

  }

  pub fn get_passwords(&self, s: &Service) -> Vec<Password>{

    let get_passwords_query = "
      SELECT * FROM passwords WHERE owner_username = :owner_username;
    ";

    let mut statement = s.db.prepare(get_passwords_query).unwrap();
    statement.bind::<&[(_, Value)]>(&[
      (":owner_username", self.username.clone().into())
    ]).unwrap();

    let mut pws:Vec<Password> = Vec::new();

    while let Ok(State::Row) = statement.next() {
      let i = statement.read::<String, _>("id").unwrap();
      let u = statement.read::<String, _>("owner_username").unwrap();
      let l = statement.read::<String, _>("login_username").unwrap();
      let d = statement.read::<String, _>("destination").unwrap();
      let p = statement.read::<Vec<u8>, _>("encrypted_password").unwrap();

      let decrypted_password = auth::decrypt_password(&self.secret, &p);

      if decrypted_password.is_ok() {
        pws.push(Password::new(i, u, l, d, decrypted_password.unwrap()))
      }
    }

    pws
  }

  pub fn search_passwords(&self, s: &Service, search: String) -> Vec<Password> {
    let search_passwords_query = "
      SELECT * FROM passwords WHERE destination LIKE :search;
    ";

    let formatted_search = format!("%{}%", search);

    let mut statement = s.db.prepare(search_passwords_query).unwrap();
    statement.bind::<&[(_, Value)]>(&[
      (":search", formatted_search.clone().into()),
    ]).unwrap();

    let mut pws:Vec<Password> = Vec::new();

    while let Ok(State::Row) = statement.next() {
      let i = statement.read::<String, _>("id").unwrap();
      let u = statement.read::<String, _>("owner_username").unwrap();
      let l = statement.read::<String, _>("login_username").unwrap();
      let d = statement.read::<String, _>("destination").unwrap();
      let p = statement.read::<Vec<u8>, _>("encrypted_password").unwrap();

      let decrypted_password = auth::decrypt_password(&self.secret, &p);

      if decrypted_password.is_ok() {
        pws.push(Password::new(i, u, l, d, decrypted_password.unwrap()))
      }
    }

    pws
  }

  pub fn copy_password(&self, s: &Service, id: String) -> Result<String, String> {
    let get_pw_query = "
      SELECT (encrypted_password) FROM passwords WHERE id = :id;
    ";

    let mut statement = s.db.prepare(get_pw_query).unwrap();
    statement.bind::<&[(_, Value)]>(&[
      (":id", id.clone().into()),
    ]).unwrap();

    let mut p: Vec<u8> = Vec::new();

    while let Ok(State::Row) = statement.next() {
      p = statement.read::<Vec<u8>, _>("encrypted_password").unwrap();
    }

    let decrypted_password = auth::decrypt_password(&self.secret, &p);

    if decrypted_password.is_ok() {
      cli_clipboard::set_contents(decrypted_password.unwrap()).unwrap();
      Ok(String::from("password copied"))
    } else {
      Err(String::from("error copying password"))
    }




  }
}


impl Service {
  pub fn new(db: sqlite::Connection) -> Self {
    Self {
      db
    }
  }




  pub fn login(&self, username: String, password: String) -> Result<User, &str> {
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
    print!("\x1B[2J\x1B[1;1H");
    println!("Creating account...");

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
        id TEXT PRIMARY KEY,
        owner_username TEXT,
        login_username TEXT,
        destination TEXT,
        encrypted_password BLOB,
        UNIQUE(login_username, destination),
        FOREIGN KEY(owner_username)
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
    let _d1 = std::fs::create_dir("~/.pjol_password_manager");
    let _d2 = std::fs::create_dir("~/.pjol_password_manager/data");
    let f = File::create_new(&path);
    if !f.is_ok() {
      panic!("unable to make db file, please make sure the directory ./data is available at the root of the project.")
    }
    println!("made file at {}", &path)
  }
  let connection = sqlite::open(path.clone()).unwrap();
  let s = Service::new(connection);
  s.init_tables();
  s
}

