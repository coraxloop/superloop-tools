pub fn script(body: &str) -> String {
    format!("#!/bin/sh\n[ \"$1\" = show ] || exit 2\n{body}\n")
}
