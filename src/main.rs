use cidr::IpCidr;
use colored::{ColoredString, Colorize};
use regex::Regex;
use std::cmp::Ordering;
use std::io;
use std::io::ErrorKind;
use std::net::SocketAddr;
use std::process;
use std::str::FromStr;
use tokio::net::TcpStream;
use tokio::task::JoinSet;
use tokio::time::{Duration, timeout};

struct ErrorCodes;
struct VerbosityLevel;

impl VerbosityLevel {
    const INFO: u8 = 0;
    const WARN: u8 = 1;
    const ERROR: u8 = 2;
    const DEBUG: u8 = 3;
}

impl ErrorCodes {
    const TEST_ERROR: i32 = 3000;
    const INVALID_VARIABLE: i32 = 3001;
    const INVALID_INPUT: i32 = 3002;
    const IMPOSSIBLE_CIDR: i32 = 3003;
    const VALID_PORT_PARSE_FAILURE: i32 = 3004;
    const SOCKET_ADDRESS_FAILED_TO_SET: i32 = 9996;
    const INVALID_VERBOSITY_LEVEL: i32 = 9997;
    const NO_VARIABLE_FOR_ERROR: i32 = 9998;
    const NO_ERROR_CODE_GIVEN: i32 = 9999;
}

#[derive(Debug)]
struct ScanResult {
    ip: SocketAddr,
    status: ConnectionStatus,
}

#[derive(Debug)]
enum ConnectionStatus {
    Open,
    Refused,
    Timeout,
    Unreachable,
}

const VERBOSITY_LEVEL: u8 = VerbosityLevel::ERROR;
#[tokio::main]
async fn main() {
    let mut set: JoinSet<ScanResult> = JoinSet::new();
    let mut network_id: String = String::new();
    let mut network_cidr: String = String::new();
    let mut port_list: Vec<u16> = Vec::new();
    let network_id_valid_pattern: Regex = Regex::new(r"^([0-9]{1,3}\.){3}[0-9]{1,3}$").unwrap();
    let network_cidr_valid_pattern: Regex = Regex::new(r"^\/{0,1}[0-9]{2}$").unwrap();
    let port_list_valid_pattern: Regex = Regex::new(r"^([0-9]{1,5}[-,])*[0-9]{1,5}$").unwrap();

    println!("Input a valid network id");
    match io::stdin().read_line(&mut network_id) {
        Ok(_) => verify_user_input(network_id.trim(), network_id_valid_pattern, "network id"),
        Err(_) => error_handler(ErrorCodes::INVALID_INPUT, line!(), None),
    }

    println!("Input a valid network cidr");
    match io::stdin().read_line(&mut network_cidr) {
        Ok(_) => verify_user_input(
            network_cidr.trim(),
            network_cidr_valid_pattern,
            "network cir",
        ),
        Err(_) => error_handler(ErrorCodes::INVALID_INPUT, line!(), None),
    }

    println!("Input a range of ports");
    let mut port_input = String::new();
    match io::stdin().read_line(&mut port_input) {
        Ok(_) => verify_user_input(port_input.trim(), port_list_valid_pattern, "port input"),
        Err(_) => error_handler(ErrorCodes::INVALID_INPUT, line!(), None),
    }

    port_list = build_port_list(port_input);

    let network: IpCidr = build_valid_network_configuration(network_id, network_cidr);

    if let IpCidr::V4(v4_cidr) = network {
        for ip in v4_cidr.iter() {
            for port in &port_list {
                let target_string: String = format!(
                    "{}:{}",
                    ip.to_string().trim().split("/").nth(0).unwrap(),
                    port
                );
                let target = match SocketAddr::from_str(&target_string) {
                    Ok(target_result) => target_result,
                    Err(_) => {
                        error_handler(ErrorCodes::SOCKET_ADDRESS_FAILED_TO_SET, line!(), None)
                    }
                };
                print_to_terminal(format!("Targeting: {}", target), VerbosityLevel::DEBUG);

                set.spawn(check_target(target));
            }
        }
    }

    print_to_terminal(String::from("Waiting for results"), VerbosityLevel::INFO);

    while let Some(res) = set.join_next().await {
        match res {
            Ok(scan_result) => match scan_result.status {
                ConnectionStatus::Open => {
                    print_to_terminal(format!("{} - Open", scan_result.ip), VerbosityLevel::INFO);
                }
                ConnectionStatus::Refused => {
                    print_to_terminal(
                        format!("{} - Refused", scan_result.ip),
                        VerbosityLevel::WARN,
                    );
                }
                _ => {
                    print_to_terminal(
                        format!("{} - Timeout", scan_result.ip),
                        VerbosityLevel::ERROR,
                    );
                }
            },
            Err(e) => {
                print_to_terminal(
                    format!("An error has occured: {}", e),
                    VerbosityLevel::ERROR,
                );
            }
        }
    }

    print_to_terminal(String::from("Scan has completed"), VerbosityLevel::INFO);
}

fn verify_user_input(input: &str, pattern: Regex, name: &str) {
    if pattern.is_match(input) {
        print_to_terminal(format!("Valid input: {}", input), VerbosityLevel::DEBUG);
    } else if input == "exit" || input == "quit" {
        println!("Exiting");
        process::exit(0)
    } else {
        error_handler(ErrorCodes::INVALID_VARIABLE, line!(), Some(name));
    }
}

fn build_port_list(port_input: String) -> Vec<u16> {
    let v: Vec<&str> = port_input.trim().split(",").collect();
    let mut return_vector: Vec<u16> = Vec::new();

    for port in v {
        if port.contains("-") {
            let range: Vec<&str> = port.trim().split("-").collect();
            let start: u16 = match range[0].parse() {
                Ok(start_result) => start_result,
                Err(_) => error_handler(
                    ErrorCodes::INVALID_VARIABLE,
                    line!(),
                    Some("port_range_start"),
                ),
            };
            let end: u16 = match range[1].parse() {
                Ok(end_result) => end_result,
                Err(_) => error_handler(
                    ErrorCodes::INVALID_VARIABLE,
                    line!(),
                    Some("port_range_end"),
                ),
            };
            for port_iter in start..end {
                print_to_terminal(
                    format!("Parsing port: {}", port_iter),
                    VerbosityLevel::DEBUG,
                );
                return_vector.push(port_iter)
            }
        } else {
            print_to_terminal(format!("Parsing port: {}", port), VerbosityLevel::DEBUG);
            let parsed_port: u16 = match port.parse() {
                Ok(parsed_port_result) => parsed_port_result,
                Err(_) => error_handler(ErrorCodes::VALID_PORT_PARSE_FAILURE, line!(), None),
            };
            return_vector.push(parsed_port)
        }
    }
    return_vector
}

fn build_valid_network_configuration(network_id: String, network_cidr: String) -> IpCidr {
    let mut network_string: String = String::new();

    if network_cidr.contains("/") {
        network_string = format!("{}{}", network_id.trim(), network_cidr.trim());
    } else {
        network_string = format!("{}/{}", network_id.trim(), network_cidr.trim());
    };

    let network: IpCidr = match IpCidr::from_str(&network_string) {
        Ok(network_string_result) => {
            print_to_terminal(
                format!("Network String: {}", network_string),
                VerbosityLevel::DEBUG,
            );
            network_string_result
        }
        Err(_) => {
            error_handler(ErrorCodes::IMPOSSIBLE_CIDR, line!(), None);
        }
    };

    network
}

async fn check_target(target: SocketAddr) -> ScanResult {
    let connect_future = TcpStream::connect(target);
    let result = timeout(Duration::from_secs(3), connect_future).await;

    let status = match result {
        Err(_) => ConnectionStatus::Timeout,
        Ok(connection_result) => match connection_result {
            Ok(_) => ConnectionStatus::Open,
            Err(e) => match e.kind() {
                ErrorKind::ConnectionRefused => ConnectionStatus::Refused,
                ErrorKind::HostUnreachable | ErrorKind::NetworkUnreachable => {
                    ConnectionStatus::Unreachable
                }
                _ => ConnectionStatus::Timeout,
            },
        },
    };
    ScanResult { ip: target, status }
}

fn error_handler(error_code: i32, line_num: u32, error_var_name: Option<&str>) -> ! {
    match error_code {
        ErrorCodes::TEST_ERROR => print_to_terminal(
            format!("{} : Test error. Hello and goodbye", error_code),
            VerbosityLevel::ERROR,
        ),
        ErrorCodes::INVALID_VARIABLE => match error_var_name {
            None => error_handler(ErrorCodes::NO_VARIABLE_FOR_ERROR, line_num, None),
            _ => {
                print_to_terminal(
                    format!(
                        "{} : An invalid value was found for {:?} on line {}",
                        error_code, error_var_name, line_num
                    ),
                    VerbosityLevel::ERROR,
                );
            }
        },
        ErrorCodes::INVALID_INPUT => print_to_terminal(
            format!(
                "{} : A non-valid input has been entered. Line: {}",
                error_code, line_num
            ),
            VerbosityLevel::ERROR,
        ),
        ErrorCodes::IMPOSSIBLE_CIDR => print_to_terminal(
            format!(
                "{} : An impossible cidr combination was entered.",
                error_code
            ),
            VerbosityLevel::ERROR,
        ),
        ErrorCodes::VALID_PORT_PARSE_FAILURE => print_to_terminal(
            format!(
                "{} : A port that was deemed valid has failed to parse. Consult a developer.",
                error_code
            ),
            VerbosityLevel::ERROR,
        ),
        ErrorCodes::SOCKET_ADDRESS_FAILED_TO_SET => print_to_terminal(
            format!("{} : Failed to assign socket.", error_code),
            VerbosityLevel::ERROR,
        ),
        ErrorCodes::INVALID_VERBOSITY_LEVEL => print_to_terminal(
            format!(
                "{} : An invalid verbosity level was passed to the print_to_terminal function. Please contact a developer. Line: {}",
                error_code, line_num
            ),
            VerbosityLevel::ERROR,
        ),
        ErrorCodes::NO_VARIABLE_FOR_ERROR => print_to_terminal(
            format!(
                "{} : An error was caught that requires a value for \"error_var_name\", but none was given. Please contact a developer. Line {}",
                error_code, line_num
            ),
            VerbosityLevel::ERROR,
        ),
        ErrorCodes::NO_ERROR_CODE_GIVEN => print_to_terminal(
            format!(
                "{} : An error was caught, but an invalid error code was given. Please consult a developer. Line: {}",
                error_code, line_num
            ),
            VerbosityLevel::ERROR,
        ),
        _ => error_handler(ErrorCodes::NO_ERROR_CODE_GIVEN, line_num, None),
    }
    process::exit(error_code);
}

fn print_to_terminal(msg: String, level: u8) {
    let mut colored_prefix: ColoredString = "".white();

    match level {
        VerbosityLevel::INFO => colored_prefix = "[INFO]".white(),
        VerbosityLevel::WARN => colored_prefix = "[WARN]".yellow(),
        VerbosityLevel::ERROR => colored_prefix = "[ERROR]".red(),
        VerbosityLevel::DEBUG => colored_prefix = "[DEBUG]".green(),
        _ => error_handler(ErrorCodes::INVALID_VERBOSITY_LEVEL, line!(), None),
    }

    match level.cmp(&VERBOSITY_LEVEL) {
        Ordering::Greater => {}
        _ => {
            if level == VerbosityLevel::ERROR {
                eprintln!("{} {}", colored_prefix, msg)
            } else {
                println!("{} {}", colored_prefix, msg)
            }
        }
    }
}
