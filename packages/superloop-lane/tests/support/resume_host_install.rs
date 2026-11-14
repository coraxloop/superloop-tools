//! Synthetic installed payloads; all custody and preflight checks are production calls.
use super::host::{directory, mapped, write};
use serde_json::json;
use std::fs;
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};
fn hash(path: &Path) -> String {
    superloop_lane::build::sha256(path).expect("payload hash")
}
pub(super) fn configure(home: &Path) -> PathBuf {
    let custody = home.join(".config/loops/alpha");
    directory(custody.clone(), 0o700);
    let template = home
        .join(".var/loops/alpha/runner-templates/codex")
        .join("a".repeat(64));
    let sockets = home.join(".var/loops/alpha/sockets");
    for (path, mode) in [
        (template.join("bin"), 0o700),
        (template.join("libexec"), 0o700),
        (sockets.clone(), 0o700),
        (sockets.join("vendor"), 0o700),
        (sockets.join("door"), 0o750),
        (custody.join("lanes"), 0o700),
        (custody.join("lanes/codex"), 0o700),
        (home.join(".cache/tmp"), 0o700),
    ] {
        directory(path, mode);
    }
    let runtime = runtime(home);
    for (name, data, mode) in [
        ("bin/codex", "pinned codex\n", 0o550),
        ("bin/codex-code-mode-host", "pinned host\n", 0o550),
        (
            "config.toml",
            "sandbox_mode = \"danger-full-access\"\n",
            0o440,
        ),
        ("AGENTS.md", "A worker charter.\n", 0o440),
        ("libexec/box-init", "fixed init\n", 0o440),
        ("libexec/ssh", "keyless stub\n", 0o550),
    ] {
        write(template.join(name), data, mode);
    }
    write(custody.join("door-service"), "registered service\n", 0o700);
    mapped(
        home,
        "import os,sys\nfrom pathlib import Path\nh=Path(sys.argv[1])\nfor p in [h/'.var/loops/alpha/sockets/door',h/'.var/loops/alpha/runner-templates/codex'/('a'*64)/'libexec/ssh']: os.chown(p,0,64000)\n",
    );
    records(home, &custody, &template, &sockets, &runtime);
    for (path, mode) in [
        (template.parent().expect("backend").to_owned(), 0o711),
        (
            template
                .parent()
                .expect("backend")
                .parent()
                .expect("templates")
                .to_owned(),
            0o711,
        ),
        (template.join("bin"), 0o550),
        (template.join("libexec"), 0o550),
        (template.clone(), 0o550),
    ] {
        directory(path, mode);
    }
    let registry = home.join(".config/loops/registry.toml");
    write(
        registry,
        format!(
            "namespace='org.superloop-tools.loophome.registry'\nversion=[1,0,0]\nloops=[{{name='alpha',uid=64000,launch='dev/alpha',runs_root='{}'}}]\n",
            home.join("runs").display()
        ),
        0o600,
    );
    write(
        custody.join("workers.toml"),
        format!(
            "runs_root='{}'\nentry_bin='{}'\ndriver_argv=['{}']\nimage_digest='sha256:{}'\ntemplate_dir='{}'\nsocket_dir='{}'\nbackend_argv={{codex=['/usr/libexec/superloop/fixture-image-codex']}}\nresources={{memory_bytes=2147483648,pids_max=128,cpu_shares=512}}\nvendor_hosts={{codex=[]}}\n",
            home.join("runs").display(),
            home.join("entry-fixture").display(),
            home.join("driver-fixture").display(),
            "a".repeat(64),
            template.display(),
            sockets.display()
        ),
        0o600,
    );
    runtime
}
fn runtime(home: &Path) -> PathBuf {
    let runtime = home.join("container-fixture");
    fs::copy("/bin/sh", &runtime).expect("native runtime stand-in");
    write(
        home.join("unshare"),
        "export TMPDIR=${PWD%/*}\nprintf '%s\\n' \"$2\" >> entry-calls\nexec /usr/bin/podman unshare \"$@\"\n",
        0o600,
    );
    write(
        home.join("image"),
        format!("printf '%s\\n' '{}'\n", "a".repeat(64)),
        0o600,
    );
    for name in ["ps", "container", "stop", "wait", "rm"] {
        write(home.join(name), "exit 0\n", 0o600);
    }
    write(
        home.join("run"),
        "cat >/dev/null\nprintf '%s\\n' '{\"type\":\"thread.started\",\"thread_id\":\"fixture-thread\"}'\n",
        0o600,
    );
    let image = std::env::current_exe().expect("driver stand-in image");
    write(
        home.join("entry-fixture"),
        format!(
            "#!/bin/sh\nif [ \"$1 $2\" = 'driver-launch --interface-version' ]; then printf '%s\\n' 'superloop-driver-entry {} 1'; exit 0; fi\nexec '{}' --fixture-driver '{}' \"$@\"\n",
            env!("CARGO_PKG_VERSION"),
            image
                .to_str()
                .expect("UTF-8 fixture image")
                .replace('\'', "'\\''"),
            home.to_str()
                .expect("UTF-8 fixture root")
                .replace('\'', "'\\''")
        ),
        0o700,
    );
    write(
        home.join("driver-fixture"),
        "#!/bin/sh\necho 'boxed-runtime 1'\n",
        0o700,
    );
    write(home.join("proxy-fixture"), "#!/bin/sh\nexit 0\n", 0o700);
    write(
        home.join("first-letter"),
        "Synthetic first dispatch.\n",
        0o600,
    );
    runtime
}

fn records(home: &Path, custody: &Path, template: &Path, sockets: &Path, runtime: &Path) {
    let image = format!("sha256:{}", "a".repeat(64));
    let codex = hash(&template.join("bin/codex"));
    let host = hash(&template.join("bin/codex-code-mode-host"));
    let init = hash(&template.join("libexec/box-init"));
    let image_program = "/usr/libexec/superloop/fixture-image-codex";
    let manifest = json!({"image_digest":image,
 "codex_sha256":codex,
 "codex_host_sha256":host,
 "config_sha256":hash(&template.join("config.toml")),
 "charter_sha256":hash(&template.join("AGENTS.md"))});
    write(
        template.join("manifest"),
        serde_json::to_vec(&manifest).expect("manifest"),
        0o440,
    );
    let report = json!({"schema":1,
 "command":"build",
 "tools_commit":"fixture",
 "package_inventory":[],
 "image_digest":image,
 "codex_sha256":codex,
 "codex_host_sha256":host,
 "codex_host_probe":{"argv":["--help"],
 "stdout":"host help",
 "sha256":host},
 "init_sha256":init,
 "codex_image_program":image_program,
 "build_environment":{"template_dir":template,
 "podman_bin":runtime,
 "codex_bin":template.join("bin/codex"),
 "codex_host_bin":template.join("bin/codex-code-mode-host")},
 "codex_exec_probe":{"argv":["exec",
 "--help"],
 "stdout":"  -m, --model\n  -c, --config\n  --json\n  --sandbox\n  --add-dir\n  --skip-git-repo-check\n  -C, --cd\n  -o, --output-last-message\n",
 "required_options":["--json",
 "--sandbox",
 "--add-dir",
 "--skip-git-repo-check",
 "-C",
 "-o"],
 "codex_sha256":codex,
 "companions":[{"name":"codex-code-mode-host",
 "path":"/usr/libexec/superloop/codex-code-mode-host",
 "sha256":host}]}});
    let generation = json!({"schema":1,
 "phase":"complete",
 "image_digest":image,
 "codex_sha256":codex,
 "codex_host_sha256":host,
 "codex_image_program":image_program,
 "proxy_bin":home.join("proxy-fixture"),
 "proxy_sha256":hash(&home.join("proxy-fixture")),
 "init_sha256":init,
 "tools_commit":"fixture",
 "template_dir":template,
 "socket_dir":sockets,
 "unit_dir":home.join(".config/systemd/user"),
 "source_fingerprint":"a".repeat(64)});
    let door = json!({"schema":2,
 "agent":{"source":"/fixture/door.toml",
 "rubric_root":"/fixture",
 "rubric_path":"/fixture/permissions/door.md",
 "executable":"/fixture/codex",
 "model":"fixture",
 "effort":"medium",
 "cap_ms":30000,
 "entry":"/fixture/entry",
 "loop_home":"/fixture/home"},
 "phase":"complete",
 "loop":"alpha",
 "template_dir":template,
 "socket_dir":sockets,
 "stub_sha256":hash(&template.join("libexec/ssh")),
 "service_sha256":hash(&custody.join("door-service")),
 "unit_dir":custody.join("units"),
 "registered":["ssh"],
 "host_door_gid":fs::metadata(sockets.join("door")).expect("host mapped group").gid()});
    for (name, value) in [
        ("image-build.json", report),
        ("install-generation.json", generation),
        ("door-install-generation.json", door),
    ] {
        write(
            custody.join(name),
            serde_json::to_vec(&value).expect("installed record"),
            0o600,
        );
    }
}
