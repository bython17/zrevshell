// Store the victim_profile in the shared directory
// inside the project_root/reverse_shell directory.
const CONFIG: &str = include_str!("../profile.json");

fn main() {
    println!("{}", CONFIG);
    println!("Hello, world!");
}
