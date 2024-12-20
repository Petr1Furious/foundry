use std::process::{Command, Output};
use std::io::{self, ErrorKind};

pub fn sign(args: &[&str]) -> io::Result<String> {
    let output: Output = Command::new("your_command")
        .args(args)
        .output()?;

    if output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        Ok(stdout.to_string())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        Err(io::Error::new(ErrorKind::Other, stderr.to_string()))
    }
}