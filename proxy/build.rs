fn main() {
    configure_me_codegen::build_script_auto().unwrap_or_else(|e| e.report_and_exit());
}
