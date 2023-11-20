use build_const::build_const;

fn main() {
    let mut consts = include!(concat!(std::env::var("OUT_DIR"), concat!("/", $mod_name)));
}
