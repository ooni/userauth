fn main() -> Result<(), Box<dyn std::error::Error>> {
    let table = ooniauth_core::benchmark::run_benchmark_table()?;
    println!("{table}");
    Ok(())
}
