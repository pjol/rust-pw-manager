mod db;
use core::str;
use std::{fs::read, io::{stdin, stdout}};


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

    let u = &user.username;
    start_user_flow(&user, &s);
    println!("logged in {}!", u);
}


fn start_user_flow(user: &User, s: &Service) {
    print!("\x1B[2J\x1B[1;1H");
    println!("Welcome, {}", user.username);
    println!();
    println!();
    println!("Type \"help\" for a list of commands.");
    take_user_input(&user, &s);
}

fn take_user_input(user: &User, s: &Service) {
    let command = read_input();
    let _help = String::from("help");
    let _add = String::from("add");
    let _getall = String::from("getall");
    let _exit = String::from("exit");
    if command == _help {
        println!("
            add:        add a new password to your database
            remove:     delete a password from your database
            getall:     get a list of all stored password destinations
            get:        get a password by its destination
            exit:       exit the program
        ");

    }
    if command == _add {
        println!("Enter destination for password:");
        println!();
        let destination = read_input();

        println!("Enter password to save:");
        println!();
        let password = read_input();

        let res = user.save_password(s, password, destination.clone());
        if res.is_ok() {
            println!("Saved password for {}", destination.clone());
        } else {
            println!("Error saving password for {}", destination);
        }
    }
    if command == _getall {
        println!("Getting passwords...");
        println!();
        let passwords = user.get_passwords(s);
        for password in passwords {
            password.print();
        }
    }
    if command == _exit {
        println!("Exiting...");
        return
    }
    take_user_input(user, s);
}

fn create_password(repeat: bool) -> String {
    if repeat {
        println!("passwords do not match.. try again");
    }
    println!();
    println!();
    println!("enter password");
    let mut p1 = termion::input::TermRead::read_passwd(&mut stdin(), &mut stdout()).unwrap().unwrap();


    println!("repeat password");
    let p2 = termion::input::TermRead::read_passwd(&mut stdin(), &mut stdout()).unwrap().unwrap();
    if p1 != p2 {
        p1 = create_password(true)
    }

    p1
}




fn login_flow(s: &Service) -> User {

    println!("enter username, or type \"create account\" to create an account");
    let username = read_input();

    if username == String::from("create account") {
        println!("enter username");
        let u = read_input();

        let p = create_password(false);


        let acc = s.create_account(u, p);
        if acc.is_ok() {
            return acc.unwrap()
        } else {
            println!("user already exists");
            return login_flow(s)
        }
    }
    println!();

    println!("enter password");
    let password = termion::input::TermRead::read_passwd(&mut stdin(), &mut stdout()).unwrap().unwrap();

    let acc = s.login(username, password);
    if acc.is_ok() {
        return acc.unwrap()
    } else {
        println!("incorrect password, try again");
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
