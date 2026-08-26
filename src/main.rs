use serde::Deserialize;
use std::env;
use std::fs::{self,File,OpenOptions};
use std::io::{BufRead,BufReader,Seek,SeekFrom,Write};
use std::path::{Path,PathBuf};
use std::process::Command;
use std::thread::sleep;
use std::time::{Duration,Instant};

const POLL_INTERVAL_SECS:u64=2;
const COMMAND_TIMEOUT_SECS:u64=20;
const MIN_MATCH_SCORE:i32=60;
const SELF_SERVICE:&str="aegira.service";

fn get_aegira_dir()->PathBuf{
    let home=env::var("HOME")
        .unwrap_or_else(|_|".".to_string());

    PathBuf::from(home).join("aegira")
}

fn get_log_file_path()->PathBuf{
    get_aegira_dir()
        .join("logs")
        .join("system.log")
}

fn get_incident_log_path()->PathBuf{
    get_aegira_dir()
        .join("logs")
        .join("incident.log")
}

fn get_builtin_rules_file()->PathBuf{
    get_aegira_dir()
        .join("rules")
        .join("builtin")
        .join("rules.json")
}

fn get_custom_rules_file()->PathBuf{
    get_aegira_dir()
        .join("rules")
        .join("custom")
        .join("rules.json")
}

fn log_incident(msg:&str){
    println!("{}",msg);

    let incident_log_path=get_incident_log_path();

    if let Some(parent)=incident_log_path.parent(){
        let _=fs::create_dir_all(parent);
    }

    if let Ok(mut file)=OpenOptions::new()
        .create(true)
        .append(true)
        .open(incident_log_path)
    {
        let _=writeln!(file,"{}",msg);
    }
}

#[derive(Debug,Deserialize,Clone)]
struct Rule{
    id:String,
    name:String,

    #[serde(default)]
    #[allow(dead_code)]
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

fn load_rules_from_file(path:&Path)->Vec<Rule>{
    if !path.exists(){
        log_incident(&format!(
            "[RULES] File does not exist: {}",
            path.display()
        ));

        return Vec::new();
    }

    let contents=match fs::read_to_string(path){
        Ok(contents)=>contents,

        Err(e)=>{
            log_incident(&format!(
                "[RULES ERROR] Failed reading {}: {}",
                path.display(),
                e
            ));

            return Vec::new();
        }
    };

    match serde_json::from_str::<Vec<Rule>>(&contents){
        Ok(rules)=>{
            for rule in &rules{
                log_incident(&format!(
                    "[RULES] Loaded: {}",
                    rule.id
                ));
            }

            rules
        }

        Err(e)=>{
            log_incident(&format!(
                "[RULES ERROR] Invalid rules file {}: {}",
                path.display(),
                e
            ));

            Vec::new()
        }
    }
}

fn check_custom_rules(){
    let custom_rules_file=get_custom_rules_file();

    if !custom_rules_file.exists(){
        log_incident(
            "[INFO] Custom rules are available in Aegira Paid"
        );

        return;
    }

    let contents=match fs::read_to_string(&custom_rules_file){
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

    let builtin_rules_file=get_builtin_rules_file();

    let rules=load_rules_from_file(
        &builtin_rules_file
    );

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

fn contains_case_insensitive(
    text:&str,
    pattern:&str
)->bool{
    text.to_lowercase()
        .contains(&pattern.to_lowercase())
}

fn calculate_match_score(
    rule:&Rule,
    incident:&str
)->i32{
    let mut score=0;

    for pattern in &rule.error_patterns{
        if contains_case_insensitive(
            incident,
            pattern
        ){
            score+=50;
        }
    }

    for pattern in &rule.context_patterns{
        if contains_case_insensitive(
            incident,
            pattern
        ){
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
        let score=calculate_match_score(
            rule,
            incident
        );

        if score>=MIN_MATCH_SCORE
            &&score>best_score
        {
            best_score=score;
            best_rule=Some(rule);
        }
    }

    best_rule.map(
        |rule|(rule,best_score)
    )
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

    let (program,program_args):(
        &str,
        Vec<&str>
    )=if executable=="systemctl"{
        let mut sudo_args=
            Vec::with_capacity(
                args.len()+1
            );

        sudo_args.push("/bin/systemctl");

        sudo_args.extend_from_slice(
            args
        );

        ("sudo",sudo_args)
    }else{
        (executable,args.to_vec())
    };

    let mut child=Command::new(program)
        .args(&program_args)
        .spawn()
        .map_err(|e|format!(
            "Failed to start {}: {}",
            executable,
            e
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
                    executable,
                    status
                ));
            }

            Ok(None)=>{
                if start.elapsed()
                    >Duration::from_secs(
                        COMMAND_TIMEOUT_SECS
                    )
                {
                    let _=child.kill();

                    return Err(format!(
                        "{} timed out after {} seconds",
                        executable,
                        COMMAND_TIMEOUT_SECS
                    ));
                }

                sleep(
                    Duration::from_millis(200)
                );
            }

            Err(e)=>{
                return Err(format!(
                    "Failed waiting for {}: {}",
                    executable,
                    e
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
            if service==SELF_SERVICE
                ||service=="aegira"
            {
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
                .args([
                    "is-active",
                    service
                ])
                .output()
            {
                Ok(output)=>{
                    let active=
                        output.status.success()
                        &&String::from_utf8_lossy(
                            &output.stdout
                        )
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

        Verification::ContainerRunning{
            container
        }=>{
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
                        &&String::from_utf8_lossy(
                            &output.stdout
                        )
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

fn recover_with_rule(
    rule:&Rule
)->Result<(),String>{
    log_incident(&format!(
        "[MATCH] Rule: {}",
        rule.name
    ));

    log_incident(&format!(
        "[MATCH] Rule ID: {}",
        rule.id
    ));

    perform_remediation(
        &rule.remediation
    )?;

    sleep(
        Duration::from_secs(2)
    );

    for attempt in 1..=5{
        log_incident(&format!(
            "[VERIFY] Verification attempt {}/5",
            attempt
        ));

        if verify_recovery(
            &rule.verification
        ){
            return Ok(());
        }

        sleep(
            Duration::from_secs(2)
        );
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
    let aegira_dir=get_aegira_dir();
    let log_file_path=get_log_file_path();

    log_incident(
        "[INFO] Aegira Free Recovery Engine Started"
    );

    log_incident(
        "[INFO] Mode: FREE"
    );

    log_incident(&format!(
        "[INFO] Aegira directory: {}",
        aegira_dir.display()
    ));

    log_incident(&format!(
        "[INFO] Monitoring log: {}",
        log_file_path.display()
    ));

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

    let file=match File::open(
        &log_file_path
    ){
        Ok(file)=>file,

        Err(e)=>{
            log_incident(&format!(
                "[FATAL] Failed to open monitored log {}: {}",
                log_file_path.display(),
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
            &log_file_path
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
            &log_file_path
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
