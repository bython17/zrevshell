use victim::run;

#[tokio::main(flavor = "current_thread")]
async fn main() {
    // println!("CPU: {}", sys::cpu_speed().unwrap());
    run().await;
}
