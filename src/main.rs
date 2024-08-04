mod db;
use core::str;
use std::{fs::read, io::{stdin, stdout, Write}, thread::sleep, time};

use db::{Service, User};

// impl Drop for ScreenState {
//     fn drop(&self) {
//         self.screen.
//     }
// }



fn main() {
    let path = String::from("./data/pw.db");
    let s = db::connect(path.clone());


    println!("connected to db at {}", path);
    print!("\x1B[2J\x1B[1;1H");


    let user = login_flow(&s);

    start_user_flow(&user, &s);
}


fn start_user_flow(user: &User, s: &Service) {
    print!("\x1B[2J\x1B[1;1H");
    println!("Welcome, {}!", user.username);
    sleep(time::Duration::from_secs(2));
    take_user_input(&user, &s, String::new());
}

fn take_user_input(user: &User, s: &Service, returned_string: String) {
    print!("\x1B[2J\x1B[1;1H");
    println!("Type \"help\" for a list of commands.");
    if returned_string.len() > 0 {
        println!();
        println!("{}", returned_string);
    }
    let command = read_input();
    let _help = String::from("help");
    let _add = String::from("add");
    let _getall = String::from("getall");
    let _exit = String::from("exit");
    let mut r = String::new();
    if command == _help {
        r = String::from("
    add:        Add a new password to your database
    remove:     Delete a password from your database
    getall:     Get a list of all stored password destinations
    get:        Copy a password to clipboard by its id
    exit:       Exit the program
");
    }


    if command == _add {
        print!("\x1B[2J\x1B[1;1H");
        println!("Enter destination for password:");
        println!();
        let destination = read_input();

        print!("\x1B[2J\x1B[1;1H");
        println!("Enter login username for password:");
        println!();
        let login_username = read_input();

        print!("\x1B[2J\x1B[1;1H");
        println!("Enter password to save:");
        println!();
        let password = read_input();
        write!(stdout(), "{}{}", termion::cursor::Up(1), termion::clear::AfterCursor);

        let res = user.save_password(s, login_username, password, destination.clone());
        if res.is_ok() {
            r = String::from(format!("Saved password for {}", destination));
        } else {
            r = String::from(format!("Error saving password for {}, password already exists", destination));
        }
        println!();
    }


    if command == _getall {
        print!("\x1B[2J\x1B[1;1H");
        println!("Getting passwords...");
        println!();
        let passwords = user.get_passwords(s);
        for password in passwords {
            password.print();
            println!();
            let mut i = 0;
            let s = termion::terminal_size().unwrap();
            while i < s.0 {
                print!("=");
                i += 1;
            }
            print!("\n");
            println!();
        }
        println!("Press enter to return");
        read_input();
    }

    if command == _exit {
        println!("Exiting...");
        return
    }

    if command.starts_with("get ") {
        let id = command.split_at(4).1;
        let c = user.copy_password(s, String::from(id));
        if c.is_ok() {
            println!("Copied to clipboard.");
        } else {
            println!("Password not found.");
        }
        sleep(time::Duration::from_secs(2));
    }
    take_user_input(user, s, r);
}

fn create_password(repeat: bool) -> String {

    if repeat {
        println!("Passwords do not match.. Try again");
    }
    println!();
    println!();
    println!("Enter password");
    println!();
    let mut p1 = termion::input::TermRead::read_passwd(&mut stdin(), &mut stdout()).unwrap().unwrap();


    println!("Repeat password");
    println!();
    let p2 = termion::input::TermRead::read_passwd(&mut stdin(), &mut stdout()).unwrap().unwrap();
    if p1 != p2 {
        p1 = create_password(true)
    }

    p1
}




fn login_flow(s: &Service) -> User {

    println!("Enter username, or type \"create account\" to create an account");
    let username = read_input();

    if username == String::from("create account") {
        print!("\x1B[2J\x1B[1;1H");
        println!("Create account:");
        println!();
        println!("Enter username");
        let u = read_input();

        let p = create_password(false);


        let acc = s.create_account(u, p);
        if acc.is_ok() {
            return acc.unwrap()
        } else {
            print!("\x1B[2J\x1B[1;1H");
            println!("User already exists");
            sleep(time::Duration::from_secs(2));
            print!("\x1B[2J\x1B[1;1H");
            return login_flow(s)
        }
    }
    println!();

    println!("Enter password");
    let password = termion::input::TermRead::read_passwd(&mut stdin(), &mut stdout()).unwrap().unwrap();

    let acc = s.login(username, password);
    if acc.is_ok() {
        return acc.unwrap()
    } else {
        println!("Incorrect username or password, try again");
        return login_flow(s)
    }
}




pub fn read_input() -> String {
    let mut input = String::new();

    stdin().read_line(&mut input).expect("invalid string");

    if let Some('\n')=input.chars().next_back() {
        input.pop();
    }
    if let Some('\r')=input.chars().next_back() {
        input.pop();
    }

    input
}
