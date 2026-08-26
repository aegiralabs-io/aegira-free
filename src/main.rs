```rust
use serde::Deserialize;
use std::fs::{self,File,OpenOptions};
use std::io::{BufRead,BufReader,Seek,SeekFrom,Write};
use std::path::Path;
use std::process::Command;
use std::thread::sleep;
use std::time::{Duration,Instant};

const LOG_FILE_PATH:&str="logs/system.log";
const INCIDENT_LOG_PATH:&str="logs/incident.log";
const BUILTIN_RULES_FILE:&str="rules/builtin/rules.json";
const CUSTOM_RULES_FILE:&str="rules/custom/rules.json";
const POLL_INTERVAL_SECS:u64=2;
const COMMAND_TIMEOUT_SECS:u64=20;
const MIN_MATCH_SCORE:i32=60;
const SELF_SERVICE:&str="aegira.service";

fn log_incident(msg:&str){
    println!("{}",msg);

    if let Some(parent)=Path::new(INCIDENT_LOG_PATH).parent(){
        let _=fs::create_dir_all(parent);
    }

    if let Ok(mut file)=OpenOptions::new()
        .create(true)
        .append(true)
        .open(INCIDENT_LOG_PATH)
    {
        let _=writeln!(file,"{}",msg);
    }
}

#[derive(Debug,Deserialize,Clone)]
struct Rule{
    id:String,
    name:String,

    #[serde(default)]
    severity:String,

    #[serde(default)]
    error_patterns:Vec<String>,

    #[serde(default)]
    context_patterns:Vec<String>,

    remediation:Remediation,
    verification:Verification,

    #[serde(default)]
    priority:i32,
}

#[derive(Debug,Deserialize,Clone)]
#[serde(tag="type")]
enum Remediation{
    #[serde(rename="service_restart")]
    ServiceRestart{service:String},

    #[serde(rename="container_restart")]
    ContainerRestart{container:String},
}

#[derive(Debug,Deserialize,Clone)]
#[serde(tag="type")]
enum Verification{
    #[serde(rename="service_active")]
    ServiceActive{service:String},

    #[serde(rename="container_running")]
    ContainerRunning{container:String},
}

fn load_rules_from_file(path:&str)->Vec<Rule>{
    if !Path::new(path).exists(){
        log_incident(&format!("[RULES] File does not exist: {}",path));
        return Vec::new();
    }

    let contents=match fs::read_to_string(path){
        Ok(contents)=>contents,
        Err(e)=>{
            log_incident(&format!(
                "[RULES ERROR] Failed reading {}: {}",
                path,e
            ));
            return Vec::new();
        }
    };

    match serde_json::from_str::<Vec<Rule>>(&contents){
        Ok(rules)=>{
            for rule in &rules{
                log_incident(&format!("[RULES] Loaded: {}",rule.id));
            }

            rules
        }

        Err(e)=>{
            log_incident(&format!(
                "[RULES ERROR] Invalid rules file {}: {}",
                path,e
            ));
            Vec::new()
        }
    }
}

fn check_custom_rules(){
    if !Path::new(CUSTOM_RULES_FILE).exists(){
        log_incident(
            "[INFO] Custom rules are available in Aegira Paid"
        );
        return;
    }

    let contents=match fs::read_to_string(CUSTOM_RULES_FILE){
        Ok(contents)=>contents,
        Err(e)=>{
            log_incident(&format!(
                "[RULES ERROR] Failed checking custom rules: {}",
                e
            ));
            return;
        }
    };

    let trimmed=contents.trim();

    if trimmed.is_empty()||trimmed=="[]"{
        log_incident(
            "[INFO] Custom rules are available in Aegira Paid"
        );
        return;
    }

    match serde_json::from_str::<Vec<Rule>>(trimmed){
        Ok(rules)=>{
            if rules.is_empty(){
                log_incident(
                    "[INFO] Custom rules are available in Aegira Paid"
                );
            }else{
                log_incident(
                    "[UPGRADE REQUIRED] Custom rules detected but are not available in Aegira Free"
                );

                log_incident(
                    "[UPGRADE REQUIRED] Upgrade to Aegira Paid to enable custom remediation rules"
                );
            }
        }

        Err(_)=>{
            log_incident(
                "[UPGRADE REQUIRED] Custom rule configuration detected but custom rules require Aegira Paid"
            );
        }
    }
}

fn load_all_rules()->Vec<Rule>{
    log_incident("[RULES] Loading built-in rules...");

    let rules=load_rules_from_file(BUILTIN_RULES_FILE);

    log_incident(&format!(
        "[RULES] Built-in rules loaded: {}",
        rules.len()
    ));

    check_custom_rules();

    log_incident(&format!(
        "[RULES] Total active rules: {}",
        rules.len()
    ));

    rules
}

fn contains_case_insensitive(text:&str,pattern:&str)->bool{
    text.to_lowercase()
        .contains(&pattern.to_lowercase())
}

fn calculate_match_score(rule:&Rule,incident:&str)->i32{
    let mut score=0;

    for pattern in &rule.error_patterns{
        if contains_case_insensitive(incident,pattern){
            score+=50;
        }
    }

    for pattern in &rule.context_patterns{
        if contains_case_insensitive(incident,pattern){
            score+=20;
        }
    }

    score+=rule.priority;
    score
}

fn find_best_rule<'a>(
    rules:&'a [Rule],
    incident:&str
)->Option<(&'a Rule,i32)>{
    let mut best_rule=None;
    let mut best_score=0;

    for rule in rules{
        let score=calculate_match_score(rule,incident);

        if score>=MIN_MATCH_SCORE&&score>best_score{
            best_score=score;
            best_rule=Some(rule);
        }
    }

    best_rule.map(|rule|(rule,best_score))
}

fn execute_command(
    executable:&str,
    args:&[&str]
)->Result<(),String>{
    log_incident(&format!(
        "[EXEC] {} {}",
        executable,
        args.join(" ")
    ));

    let (program,program_args):(&str,Vec<&str>)=
        if executable=="systemctl"{
            let mut sudo_args=Vec::with_capacity(args.len()+1);
            sudo_args.push("/bin/systemctl");
            sudo_args.extend_from_slice(args);
            ("sudo",sudo_args)
        }else{
            (executable,args.to_vec())
        };

    let mut child=Command::new(program)
        .args(&program_args)
        .spawn()
        .map_err(|e|format!(
            "Failed to start {}: {}",
            executable,e
        ))?;

    let start=Instant::now();

    loop{
        match child.try_wait(){
            Ok(Some(status))=>{
                if status.success(){
                    return Ok(());
                }

                return Err(format!(
                    "{} exited with status {}",
                    executable,status
                ));
            }

            Ok(None)=>{
                if start.elapsed()
                    >Duration::from_secs(COMMAND_TIMEOUT_SECS)
                {
                    let _=child.kill();

                    return Err(format!(
                        "{} timed out after {} seconds",
                        executable,
                        COMMAND_TIMEOUT_SECS
                    ));
                }

                sleep(Duration::from_millis(200));
            }

            Err(e)=>{
                return Err(format!(
                    "Failed waiting for {}: {}",
                    executable,e
                ));
            }
        }
    }
}

fn perform_remediation(
    remediation:&Remediation
)->Result<(),String>{
    match remediation{
        Remediation::ServiceRestart{service}=>{
            if service==SELF_SERVICE||service=="aegira"{
                return Err(
                    "Refusing remediation: rule attempts to restart Aegira itself"
                    .to_string()
                );
            }

            log_incident(&format!(
                "[RECOVERY] Restarting service: {}",
                service
            ));

            execute_command(
                "systemctl",
                &["restart",service]
            )
        }

        Remediation::ContainerRestart{container}=>{
            log_incident(&format!(
                "[RECOVERY] Restarting container: {}",
                container
            ));

            execute_command(
                "docker",
                &["restart",container]
            )
        }
    }
}

fn verify_recovery(
    verification:&Verification
)->bool{
    match verification{
        Verification::ServiceActive{service}=>{
            log_incident(&format!(
                "[VERIFY] Checking service: {}",
                service
            ));

            match Command::new("sudo")
                .arg("/bin/systemctl")
                .args(["is-active",service])
                .output()
            {
                Ok(output)=>{
                    let active=
                        output.status.success()
                        &&String::from_utf8_lossy(&output.stdout)
                            .trim()=="active";

                    if active{
                        log_incident(
                            "[VERIFY] Service is active"
                        );
                    }else{
                        log_incident(
                            "[VERIFY] Service is NOT active"
                        );
                    }

                    active
                }

                Err(e)=>{
                    log_incident(&format!(
                        "[VERIFY ERROR] {}",
                        e
                    ));

                    false
                }
            }
        }

        Verification::ContainerRunning{container}=>{
            log_incident(&format!(
                "[VERIFY] Checking container: {}",
                container
            ));

            match Command::new("docker")
                .args([
                    "inspect",
                    "-f",
                    "{{.State.Running}}",
                    container
                ])
                .output()
            {
                Ok(output)=>{
                    let running=
                        output.status.success()
                        &&String::from_utf8_lossy(&output.stdout)
                            .trim()=="true";

                    if running{
                        log_incident(
                            "[VERIFY] Container is running"
                        );
                    }else{
                        log_incident(
                            "[VERIFY] Container is NOT running"
                        );
                    }

                    running
                }

                Err(e)=>{
                    log_incident(&format!(
                        "[VERIFY ERROR] {}",
                        e
                    ));

                    false
                }
            }
        }
    }
}

fn recover_with_rule(rule:&Rule)->Result<(),String>{
    log_incident(&format!(
        "[MATCH] Rule: {}",
        rule.name
    ));

    log_incident(&format!(
        "[MATCH] Rule ID: {}",
        rule.id
    ));

    perform_remediation(&rule.remediation)?;

    sleep(Duration::from_secs(2));

    for attempt in 1..=5{
        log_incident(&format!(
            "[VERIFY] Verification attempt {}/5",
            attempt
        ));

        if verify_recovery(&rule.verification){
            return Ok(());
        }

        sleep(Duration::from_secs(2));
    }

    Err(
        "Remediation executed but health verification failed"
        .to_string()
    )
}

fn process_incident(
    rules:&[Rule],
    incident:&str
){
    let start=Instant::now();

    log_incident(&format!(
        "[WATCHER] Incident detected: {}",
        incident
    ));

    log_incident(
        "================ INCIDENT ================"
    );

    log_incident(incident);

    let (rule,score)=match find_best_rule(
        rules,
        incident
    ){
        Some(result)=>result,

        None=>{
            log_incident(
                "[MATCH] No known remediation rule found"
            );

            log_incident(
                "[MANUAL ACTION] Unknown incident requires investigation"
            );

            return;
        }
    };

    log_incident(&format!(
        "[MATCH] Confidence score: {}",
        score
    ));

    match recover_with_rule(rule){
        Ok(())=>{
            log_incident(&format!(
                "[RESOLVED] Incident automatically recovered in {:.2?}",
                start.elapsed()
            ));
        }

        Err(e)=>{
            log_incident(&format!(
                "[RECOVERY FAILED] {}",
                e
            ));

            log_incident(&format!(
                "[MANUAL ACTION] Rule '{}' requires intervention",
                rule.id
            ));
        }
    }
}

fn main(){
    log_incident(
        "[INFO] Aegira Free Recovery Engine Started"
    );

    log_incident(
        "[INFO] Mode: FREE"
    );

    let rules=load_all_rules();

    if rules.is_empty(){
        log_incident(
            "[WARNING] No remediation rules loaded"
        );
    }else{
        log_incident(&format!(
            "[INFO] {} remediation rules ready",
            rules.len()
        ));
    }

    let file=match File::open(LOG_FILE_PATH){
        Ok(file)=>file,

        Err(e)=>{
            log_incident(&format!(
                "[FATAL] Failed to open monitored log: {}",
                e
            ));
            return;
        }
    };

    let mut reader=BufReader::new(file);

    let mut position=match reader.seek(
        SeekFrom::End(0)
    ){
        Ok(position)=>position,

        Err(e)=>{
            log_incident(&format!(
                "[FATAL] Failed to seek log: {}",
                e
            ));
            return;
        }
    };

    log_incident(
        "[INFO] Monitoring new log entries..."
    );

    loop{
        let metadata=match fs::metadata(
            LOG_FILE_PATH
        ){
            Ok(metadata)=>metadata,

            Err(e)=>{
                log_incident(&format!(
                    "[ERROR] Failed to stat log: {}",
                    e
                ));

                sleep(
                    Duration::from_secs(
                        POLL_INTERVAL_SECS
                    )
                );

                continue;
            }
        };

        let file_size=metadata.len();

        if file_size<position{
            log_incident(
                "[INFO] Log rotation/truncation detected"
            );

            position=0;
        }

        if file_size==position{
            sleep(
                Duration::from_secs(
                    POLL_INTERVAL_SECS
                )
            );

            continue;
        }

        let file=match File::open(
            LOG_FILE_PATH
        ){
            Ok(file)=>file,

            Err(e)=>{
                log_incident(&format!(
                    "[ERROR] Failed to open log: {}",
                    e
                ));

                sleep(
                    Duration::from_secs(
                        POLL_INTERVAL_SECS
                    )
                );

                continue;
            }
        };

        let mut reader=BufReader::new(file);

        if let Err(e)=reader.seek(
            SeekFrom::Start(position)
        ){
            log_incident(&format!(
                "[ERROR] Failed to seek log: {}",
                e
            ));

            sleep(
                Duration::from_secs(
                    POLL_INTERVAL_SECS
                )
            );

            continue;
        }

        loop{
            let mut line=String::new();

            let bytes_read=match reader.read_line(
                &mut line
            ){
                Ok(bytes)=>bytes,

                Err(e)=>{
                    log_incident(&format!(
                        "[ERROR] Failed reading log: {}",
                        e
                    ));

                    break;
                }
            };

            if bytes_read==0{
                break;
            }

            position+=bytes_read as u64;

            let trimmed=line.trim();

            if !trimmed.contains("[ERROR]")
                &&!trimmed.contains("[CRITICAL]")
            {
                continue;
            }

            process_incident(
                &rules,
                trimmed
            );
        }

        sleep(
            Duration::from_secs(
                POLL_INTERVAL_SECS
            )
        );
    }
}
```
