mod data;

use bitcoin_wallet::bitcoin::secp256k1::{Secp256k1, All};
use bitcoin_wallet::bitcoin::network::constants::Network;
use bitcoin_wallet::bitcoin::Address;
use bitcoin_wallet::bitcoin::util::bip32::{ExtendedPrivKey, ExtendedPubKey, DerivationPath};
use std::{
    io,
    fs::OpenOptions,
    fs::File,
    io::Write,
    time::Instant,
    time::Duration,
    io::{BufRead, BufReader},
    path::Path,
};
use std::collections::HashSet;
use bip39::{Mnemonic, MnemonicType, Language};
use rand::Rng;
use tokio::task;
use ring::{pbkdf2};
use std::sync::{Arc, RwLock, RwLockReadGuard};

#[tokio::main]
async fn main() {
    let file_cong = "conf.txt";
    //Чтение настроек, и если их нет создадим
    //-----------------------------------------------------------------
    let conf = match lines_from_file(&file_cong) {
        Ok(text) => {
            println!("Параметры загружены\n");
            text
        }
        Err(_) => {
            println!("Параметры не найдены , создание и установка в режим измерения скорости\n");
            let t = data::get_conf_text(num_cpus::get().to_string());
            add_v_file(&file_cong,&t.as_str() );
            add_v_file("test_mnemonic.txt", data::get_text_text_info().as_str());
            lines_from_file(file_cong).expect("1111")
        }
    };
    //---------------------------------------------------------------------

    let stroka_1_all = &conf[1].to_string();
    let akk: u32 = first_word(stroka_1_all).to_string().parse::<u32>().unwrap() + 1;

    let stroka_2_all = &conf[2].to_string();
    let privw: u32 = first_word(stroka_2_all).to_string().parse::<u32>().unwrap() + 1;

    let stroka_3_all = &conf[3].to_string();
    let pubw: u32 = first_word(stroka_3_all).to_string().parse::<u32>().unwrap() + 1;

    let stroka_4_all = &conf[4].to_string();
    let mnemonik_variant: bool = if first_word(stroka_4_all) == "1" { true } else { false };

    let stroka_5_all = &conf[5].to_string();
    let num_seed: u8 = first_word(stroka_5_all).to_string().parse::<u8>().unwrap();

    let stroka_6_all = &conf[6].to_string();
    let mut num_cores: u8 = first_word(stroka_6_all).to_string().parse::<u8>().unwrap();

    //---------------------------------------------------------------------------------------------
    println!("----------Ищет совпадения адресов ----------");
    println!("--------Искомые адреса должны лежать рядом в all_wallets.txt-------\n");
    println!("\
    ---------------Рядом должен лежать ёще conf.txt--------------------\n");
    println!("conf:\
    \nАккаунты-{akk}\
    \nВнутрение адреса-{privw}\
    \nВнешние адреса-{pubw}\
    \nВозможные варианты-{mnemonik_variant}\
    \nДлина сид фразы-{num_seed}\
    \nЯдра CPU-{num_cores}\n");

    println!("\
    -----------------------Если чудо произойдёт:----------------------\n\
    --------------------выведется результат в консоль------------------\n\
    -------------------сид фраза запишеться BOBLO.txt-----------------\n\
    -------------будет лежать рядом(создавать не обязательно)----------\n");

    let mut bench = false;
    if num_cores == 0 {
        println!("---------------------------------------------------");
        println!("--------------Режим измерения скорости-------------");
        println!("--------------------------------------------------");
        bench = true;
        num_cores = 1;
    }

    println!("---Из {} логических ядер задействовано:{}---\n", num_cpus::get(), num_cores);

    let file_content = match lines_from_file("all_wallets.txt") {
        Ok(file) => {
            println!("Адресов в файле: {}", file.len());
            file
        }
        Err(_) => {
            println!("all_wallets.txt не найден , загружаю встроенный список");
            let dockerfile = include_str!("all_wallets.txt");
            let mut vs: Vec<String> = vec![];
            for c in dockerfile.split("\n") {
                vs.push(c.to_string());
            }
            add_v_file("all_wallets.txt", dockerfile);
            vs
        }
    };

    let mut database = HashSet::new();
    for addres in file_content.iter() {
        database.insert(addres.to_string());
    }

    println!("Загруженно в базу {:?} адресов.\n", database.len());
    let database_ = Arc::new(RwLock::new(database));

    let mut seed_schet = num_seed;
    let mut iseed = 0;
    let size_seed_list = [12, 15, 18, 21, 24];

    for _ in 0..num_cores {
        //Случайная длинна сид
        if num_seed == 0 {
            let mut rng = rand::thread_rng();
            seed_schet = size_seed_list[rng.gen_range(0..5)];
        }
        //По возрастанию
        if num_seed == 1 {
            seed_schet = size_seed_list[iseed];
            iseed = iseed + 1;
            if iseed == 5 { iseed = 0; }
        }

        let clone_database_ = database_.clone();
        task::spawn_blocking(move || {
            let current_core = std::thread::current().id();
            let db = clone_database_.read().unwrap();
            println!("Процесс {:?} запущен seed: {} слов\n", &current_core, &seed_schet);
            process(&db, bench, akk, privw, pubw, mnemonik_variant, seed_schet);
        });
    }
}

fn process(file_content: &RwLockReadGuard<HashSet<String>>, bench: bool, akk: u32, privw: u32, pubw: u32, mnemonik_variant: bool, num_seed: u8) {
    let mut start = Instant::now();
    let mut speed: u32 = 0;
    let mut rng = rand::thread_rng();
    let mut test_find = false;
    let mut time_test = 0;
    loop {
        let mut list_mnemonik = Vec::new();

        if mnemonik_variant {
            let mut mnemonic = String::from("");
            for _i in 0..num_seed - 1 {
                let n: u32 = rng.gen_range(0..2048);
                let mut word = data::WORDS[n as usize].to_string();
                word.push(' ');
                mnemonic.push_str(&word);
            }

            for i in 0..2048 {
                let mut mnemonic_test = String::from(&mnemonic);
                let word12 = data::WORDS[i as usize].to_string();
                mnemonic_test.push_str(&word12);
                if Mnemonic::validate(&mnemonic_test, Language::English).is_ok() {
                    list_mnemonik.push(mnemonic_test);
                }
            }
            if bench {
                println!("Всего комбинаций для {mnemonic} {} штук", list_mnemonik.len());
            }
        } else {
            list_mnemonik.push(get_seed(num_seed));
        }



        for mut mnemonic_x in list_mnemonik {

            //Для теста подставим тестовую фразу
            let seed: [u8; 64] = match test_find {
                true => {
                    test_find = false;
                    mnemonic_x = "wool tourist shoe hurry galaxy grow okay element arrange submit solve adjust".to_string();
                    seed_from_mnemonic(&mnemonic_x, "mnemonic".as_bytes())
                }
                false => { seed_from_mnemonic(&mnemonic_x, "mnemonic".as_bytes())}
            };

            for i_akk in 0..akk {
                for i_in in 0..privw {
                    for i in 0..pubw {
                        let address44 = address_from_seed_bip44(&seed, &Secp256k1::new(), i_akk, i_in, i);
                        let address49 = address_from_seed_bip49(&seed, &Secp256k1::new(), i_akk, i_in, i);
                        let address84 = address_from_seed_bip84(&seed, &Secp256k1::new(), i_akk, i_in, i);
                        let addresa = [address44, address84, address49];
                        for a in addresa {

                            if file_content.contains(&a) {
                                println!("=======================================================");
                                println!("Adress:{}", &a);
                                println!("SEED:{}", &mnemonic_x);
                                let s = format!("==================================\nAdress:{}\nSEED:{}\n\
                                ==================================\n",&a, &mnemonic_x);
                                add_v_file("BOBLO.txt", &s);
                                println!("=======================================================\n\
                                Сохранено в BOBLO.txt\n\
                                =======================================================\n");
                            }

                            if bench {
                                //после ~5 секунд включим тест
                                time_test = time_test + 1;
                                if time_test == 200 { test_find = true; }

                                println!("SEED:{}  m/*'/0'/{}'/{}/{}/{}",&mnemonic_x,&i_akk, &i_in, &i, &a);
                                speed = speed + 1;
                                if start.elapsed() >= Duration::from_secs(1) {
                                    println!("----------------------------------------");
                                    println!("Проверил {:?} комбинаций за 1 сек ", speed);
                                    println!("----------------------------------------");
                                    start = Instant::now();
                                    speed = 0;
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

fn first_word(s: &String) -> &str {
    let bytes = s.as_bytes();
    for (i, &item) in bytes.iter().enumerate() {
        if item == b' ' {
            return &s[0..i];
        }
    }
    &s[..]
}

fn get_seed(n: u8) -> String {
    match n {
        12 => Mnemonic::new(MnemonicType::Words12, Language::English).phrase().to_string(),
        15 => Mnemonic::new(MnemonicType::Words15, Language::English).phrase().to_string(),
        18 => Mnemonic::new(MnemonicType::Words18, Language::English).phrase().to_string(),
        21 => Mnemonic::new(MnemonicType::Words21, Language::English).phrase().to_string(),
        24 => Mnemonic::new(MnemonicType::Words24, Language::English).phrase().to_string(),
        _ => { "non".to_string() }
    }
}

fn add_v_file(name: &str, data: &str) {
    OpenOptions::new()
        .read(true)
        .append(true)
        .create(true)
        .open(name)
        .expect("cannot open file")
        .write(data.as_bytes())
        .expect("write failed");
}

fn lines_from_file(filename: impl AsRef<Path>) -> io::Result<Vec<String>> {
    BufReader::new(File::open(filename)?).lines().collect()
}

fn seed_from_mnemonic(mnemonic: &String, passphrase: &[u8]) -> [u8; 64] {
    let mut output = [0u8; 64];
    let iterations: std::num::NonZeroU32 = std::num::NonZeroU32::new(2048).unwrap();
    pbkdf2::derive(pbkdf2::PBKDF2_HMAC_SHA512, iterations, passphrase, mnemonic.as_bytes(), &mut output);
    output
}

fn address_from_seed_bip84(seed: &[u8], secp: &Secp256k1<All>, akk: u32, n_wallet_in: u32, n_wallet: u32) -> String {
    let master_private_key = ExtendedPrivKey::new_master(Network::Bitcoin, &seed).unwrap();
    let path: DerivationPath = (format!("m/84'/0'/{}'/{}/{}", akk, n_wallet_in, n_wallet)).parse().unwrap();
    let child_priv = master_private_key.derive_priv(&secp, &path).unwrap();
    let child_pub = ExtendedPubKey::from_private(&secp, &child_priv);
    let a: Address = Address::p2wpkh(&child_pub.public_key, Network::Bitcoin);
    return a.to_string();
}

fn address_from_seed_bip49(seed: &[u8], secp: &Secp256k1<All>, akk: u32, n_wallet_in: u32, n_wallet: u32) -> String {
    let master_private_key = ExtendedPrivKey::new_master(Network::Bitcoin, &seed).unwrap();
    let path: DerivationPath = (format!("m/49'/0'/{}'/{}/{}", akk, n_wallet_in, n_wallet)).parse().unwrap();
    let child_priv = master_private_key.derive_priv(&secp, &path).unwrap();
    let child_pub = ExtendedPubKey::from_private(&secp, &child_priv);
    let a: Address = Address::p2shwpkh(&child_pub.public_key, Network::Bitcoin);
    return a.to_string();
}

fn address_from_seed_bip44(seed: &[u8], secp: &Secp256k1<All>, akk: u32, n_wallet_in: u32, n_wallet: u32) -> String {
    let master_private_key = ExtendedPrivKey::new_master(Network::Bitcoin, &seed).unwrap();
    let path: DerivationPath = (format!("m/44'/0'/{}'/{}/{}", akk, n_wallet_in, n_wallet)).parse().unwrap();
    let child_priv = master_private_key.derive_priv(&secp, &path).unwrap();
    let child_pub = ExtendedPubKey::from_private(&secp, &child_priv);
    let a: Address = Address::p2pkh(&child_pub.public_key, Network::Bitcoin);
    return a.to_string();
}